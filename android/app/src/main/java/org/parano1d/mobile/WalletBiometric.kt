package org.parano1d.mobile

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

/** Biometric protection for UI access, independent of wallet encryption. */
internal object WalletBiometricStore {
    private const val PREF = "parano1c_biometric_v1"
    private const val ALIAS = "parano1c_biometric_access_v1"
    private val token = "Parano1c biometric UI access V1".toByteArray(Charsets.UTF_8)

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    fun enabled(ctx: Context): Boolean =
        prefs(ctx).contains("ciphertext") && prefs(ctx).contains("iv")

    fun available(ctx: Context): Boolean =
        BiometricManager.from(ctx).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS

    fun disable(ctx: Context) {
        check(prefs(ctx).edit().clear().commit())
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            if (containsAlias(ALIAS)) deleteEntry(ALIAS)
        }
    }

    fun cipher(ctx: Context, enrolling: Boolean): Cipher {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = if (enrolling) {
            disable(ctx)
            val builder = KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)

            if (Build.VERSION.SDK_INT >= 30) {
                builder.setUserAuthenticationParameters(
                    0, KeyProperties.AUTH_BIOMETRIC_STRONG
                )
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }
            KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
            ).apply {
                init(builder.build())
            }.generateKey()
        } else {
            store.getKey(ALIAS, null) as? SecretKey
                ?: error("Biometric key unavailable. Use PIN and enable biometrics again.")
        }

        return Cipher.getInstance("AES/CBC/PKCS7Padding").apply {
            if (enrolling) {
                init(Cipher.ENCRYPT_MODE, key)
            } else {
                val iv = Base64.decode(
                    prefs(ctx).getString("iv", null)
                        ?: error("Biometric configuration unavailable."),
                    Base64.NO_WRAP
                )
                init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
            }
        }
    }

    fun finish(ctx: Context, cipher: Cipher, enrolling: Boolean) {
        if (enrolling) {
            val encrypted = cipher.doFinal(token)
            check(prefs(ctx).edit()
                .putString("ciphertext", Base64.encodeToString(encrypted, Base64.NO_WRAP))
                .putString("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                .commit())
        } else {
            val encrypted = Base64.decode(
                prefs(ctx).getString("ciphertext", null)
                    ?: error("Biometric configuration unavailable."),
                Base64.NO_WRAP
            )
            check(MessageDigest.isEqual(token, cipher.doFinal(encrypted)))
        }
    }
}

/** Cancellation invalidates pending callbacks before cancelling the system prompt. */
private class WalletBiometricSession(
    private val activity: FragmentActivity,
    private val success: () -> Unit
) {
    private var active = false
    private var enrolling = false
    private var prompt: BiometricPrompt? = null
    private fun createPrompt() = BiometricPrompt(
        activity,
        ContextCompat.getMainExecutor(activity),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(
                result: BiometricPrompt.AuthenticationResult
            ) {
                if (!active) return
                active = false
                if (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return
                try {
                    val cipher = result.cryptoObject?.cipher
                        ?: error("Biometric verification unavailable.")
                    WalletBiometricStore.finish(activity, cipher, enrolling)
                    success()
                } catch (_: Exception) {
                    showError()
                }
            }

            override fun onAuthenticationError(code: Int, text: CharSequence) {
                if (!active) return
                active = false
                if (code != BiometricPrompt.ERROR_NEGATIVE_BUTTON &&
                    code != BiometricPrompt.ERROR_USER_CANCELED &&
                    code != BiometricPrompt.ERROR_CANCELED) {
                    Toast.makeText(activity, text, Toast.LENGTH_LONG).show()
                }
            }
        }
    )

    fun cancel() {
        val wasActive = active
        active = false
        if (wasActive) prompt?.cancelAuthentication()
        prompt = null
    }

    fun authenticate(enroll: Boolean = false) {
        if (active ||
            !activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return
        if (!WalletBiometricStore.available(activity)) {
            Toast.makeText(
                activity,
                WalletLanguage.uiString("Biometrics unavailable. Use PIN, or enroll a fingerprint in Android Settings."),
                Toast.LENGTH_LONG
            ).show()
            return
        }
        try {
            val cipher = WalletBiometricStore.cipher(activity, enroll)
            enrolling = enroll
            active = true
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(if (enroll) WalletLanguage.uiString("Enable biometric unlock") else WalletLanguage.string(activity, R.string.p1_pin_unlock_wallet))
                .setSubtitle(WalletLanguage.uiString("Authenticate using your fingerprint or supported biometrics"))
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText(WalletLanguage.uiString(if (enroll) "CANCEL" else "Use PIN"))
                .build()
            val currentPrompt = createPrompt()
            prompt = currentPrompt
            currentPrompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        } catch (_: Exception) {
            active = false
            showError()
        }
    }

    private fun showError() {
        Toast.makeText(
            activity,
            WalletLanguage.uiString("Biometric verification unavailable. Use PIN and enable biometrics again in Settings."),
            Toast.LENGTH_LONG
        ).show()
    }
}

@Composable
private fun rememberBiometricSession(onSuccess: () -> Unit): WalletBiometricSession {
    val activity = LocalContext.current as FragmentActivity
    val latestSuccess by rememberUpdatedState(onSuccess)
    val session = remember(activity) {
        WalletBiometricSession(activity) { latestSuccess() }
    }
    DisposableEffect(activity, session) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) session.cancel()
        }
        activity.lifecycle.addObserver(observer)
        onDispose {
            session.cancel()
            activity.lifecycle.removeObserver(observer)
        }
    }
    return session
}

@Composable
internal fun rememberWalletBiometricUnlock(
    unlocked: Boolean,
    onUnlock: () -> Unit
): () -> Unit {
    val activity = LocalContext.current as FragmentActivity
    val latestUnlocked by rememberUpdatedState(unlocked)
    val session = rememberBiometricSession(onUnlock)
    var attempted by remember { mutableStateOf(false) }

    fun automaticPrompt() {
        if (!latestUnlocked && !attempted &&
            PinStore.exists(activity) && WalletBiometricStore.enabled(activity) &&
            activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
            attempted = true
            session.authenticate()
        }
    }

    DisposableEffect(activity, session) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_STOP -> attempted = false
                Lifecycle.Event.ON_RESUME -> automaticPrompt()
                else -> Unit
            }
        }
        activity.lifecycle.addObserver(observer)
        onDispose { activity.lifecycle.removeObserver(observer) }
    }

    LaunchedEffect(unlocked) {
        if (unlocked) session.cancel() else automaticPrompt()
    }

    return {
        if (!latestUnlocked) {
            attempted = true
            session.authenticate()
        }
    }
}

@Composable
internal fun WalletBiometricSetting() {
    val ctx = LocalContext.current
    var enabled by remember { mutableStateOf(WalletBiometricStore.enabled(ctx)) }
    var dialog by remember { mutableStateOf(false) }
    var pin by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }
    val session = rememberBiometricSession { enabled = true }

    WalletSafetyCard(
        enabled = enabled,
        error = if (dialog) "" else error,
        onToggle = {
            if (enabled) {
                try {
                    session.cancel()
                    WalletBiometricStore.disable(ctx)
                    enabled = false
                    error = ""
                } catch (_: Exception) {
                    error = WalletLanguage.uiString("Could not disable biometrics.")
                }
            } else {
                pin = ""
                error = ""
                dialog = true
            }
        }
    )

    if (dialog) {
        AlertDialog(
            onDismissRequest = { dialog = false; pin = ""; error = "" },
            title = { Text(WalletLanguage.string(ctx, R.string.p1_pin_confirm_pin)) },
            text = {
                Column {
                    OutlinedTextField(
                        value = pin,
                        onValueChange = {
                            pin = it.filter { c -> c in '0'..'9' }.take(6)
                            error = ""
                        },
                        label = { Text(WalletLanguage.string(ctx, R.string.p1_pin_pin_code)) },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.NumberPassword
                        )
                    )
                    if (error.isNotEmpty()) Text(error, color = ParanoDanger)
                }
            },
            confirmButton = {
                TextButton(
                    enabled = pin.length == 6,
                    onClick = {
                        val entered = pin
                        pin = ""
                        try {
                            if (PinStore.verify(ctx, entered)) {
                                dialog = false
                                error = ""
                                session.authenticate(enroll = true)
                            } else {
                                error = if (PinStore.remaining(ctx) > 0L)
                                    WalletLanguage.string(ctx, R.string.p1_pin_too_many_attempts)
                                else WalletLanguage.string(ctx, R.string.p1_pin_incorrect_pin)
                            }
                        } catch (_: Exception) {
                            error = WalletLanguage.string(ctx, R.string.p1_pin_pin_storage_error)
                        }
                    }
                ) { Text(WalletLanguage.string(ctx, R.string.p1_pin_continue)) }
            },
            dismissButton = {
                TextButton(onClick = { dialog = false; pin = ""; error = "" }) {
                    Text(WalletLanguage.uiString("CANCEL"))
                }
            }
        )
    }
}
