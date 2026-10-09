package org.parano1d.mobile

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.activity.ComponentActivity
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/** UI access PIN. Not a wallet seed/password, and not a substitute for wallet encryption. */
private object PinStore {
    private const val PREF = "parano1c_app_pin_v1"
    private const val ALIAS = "parano1c_app_pin_hmac_v1"
    private const val HEADER = "Parano1c UI PIN V1|"
    private const val BACKOFF_START = 5
    private const val LOCKOUT_MS = 60_000L

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
    fun exists(ctx: Context): Boolean = prefs(ctx).contains("verifier")

    private fun secret(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setDigests(KeyProperties.DIGEST_SHA256).build())
        return generator.generateKey()
    }

    private fun verifier(pin: String, salt: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(secret())
        mac.update(HEADER.toByteArray(Charsets.UTF_8))
        mac.update(salt)
        return mac.doFinal(pin.toByteArray(Charsets.UTF_8))
    }

    fun create(ctx: Context, pin: String) {
        require(pin.matches(Regex("[0-9]{6}")))
        check(!exists(ctx)) { "PIN already configured" }
        val salt = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val digest = verifier(pin, salt)
        check(prefs(ctx).edit()
            .putString("salt", Base64.encodeToString(salt, Base64.NO_WRAP))
            .putString("verifier", Base64.encodeToString(digest, Base64.NO_WRAP))
            .putInt("failures", 0).putLong("deadline_wall", 0L).commit())
    }

    fun remaining(ctx: Context): Long =
        (prefs(ctx).getLong("deadline_wall", 0L) - System.currentTimeMillis()).coerceAtLeast(0L)

    fun verify(ctx: Context, pin: String): Boolean {
        if (remaining(ctx) > 0L) return false
        val p = prefs(ctx)
        val salt = Base64.decode(p.getString("salt", null) ?: return false, Base64.NO_WRAP)
        val expected = Base64.decode(p.getString("verifier", null) ?: return false, Base64.NO_WRAP)
        val correct = MessageDigest.isEqual(expected, verifier(pin, salt))
        if (correct) {
            check(p.edit().putInt("failures", 0).putLong("deadline_wall", 0L).commit())
            return true
        }
        val failures = p.getInt("failures", 0) + 1
        val deadline = if (failures >= BACKOFF_START) System.currentTimeMillis() + LOCKOUT_MS else 0L
        check(p.edit().putInt("failures", if (failures >= BACKOFF_START) 0 else failures)
            .putLong("deadline_wall", deadline).commit())
        return false
    }
}

/** Activity ON_STOP invalidates only UI authentication; node service and wallet data remain untouched. */
@Composable
internal fun WalletPinGate(content: @Composable () -> Unit) {
    val ctx = LocalContext.current
    val activity = ctx as ComponentActivity
    var unlocked by remember { mutableStateOf(false) }
    var hasPin by remember { mutableStateOf(PinStore.exists(ctx)) }
    var first by remember { mutableStateOf("") }
    var typed by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var errorState by remember { mutableStateOf(false) }

    DisposableEffect(activity) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) {
                unlocked = false
                typed = ""
                first = ""
                message = ""
            }
        }
        activity.lifecycle.addObserver(observer)
        onDispose { activity.lifecycle.removeObserver(observer) }
    }

    if (unlocked) {
        content()
        return
    }

    val t = { key: String ->
        val localized = WalletLanguage.resourceContext(ctx)
        val id = localized.resources.getIdentifier(
            "p1_pin_" + key.lowercase(java.util.Locale.ROOT).replace(" ", "_"),
            "string", localized.packageName
        )
        if (id != 0) localized.getString(id) else key
    }
    ParanoTheme {
        Column(
            modifier = Modifier.fillMaxSize().background(ParanoBackground)
                .safeDrawingPadding().padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                when {
                    !hasPin && first.isEmpty() -> t("CREATE PIN")
                    !hasPin -> t("CONFIRM PIN")
                    else -> t("UNLOCK WALLET")
                },
                color = ParanoText,
                style = MaterialTheme.typography.headlineMedium
            )
            Spacer(Modifier.height(12.dp))
            Text(t("SIX DIGIT PIN"), color = ParanoMuted)
            Spacer(Modifier.height(20.dp))
            OutlinedTextField(
                value = typed,
                onValueChange = { next ->
                    typed = next.filter { it in '0'..'9' }.take(6)
                    message = ""
                },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                label = { Text(t("PIN CODE")) }
            )
            if (message.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                Text(message, color = if (errorState) ParanoDanger else ParanoMuted)
            }
            Spacer(Modifier.height(18.dp))
            Button(
                enabled = typed.length == 6,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = ParanoGreen, contentColor = ParanoBackground),
                onClick = {
                    val pin = typed
                    typed = ""
                    try {
                        when {
                            !hasPin && first.isEmpty() -> {
                                first = pin
                                message = ""
                            }
                            !hasPin -> {
                                if (pin != first) {
                                    first = ""
                                    message = t("PINS DO NOT MATCH")
                                    errorState = true
                                } else {
                                    PinStore.create(ctx, pin)
                                    first = ""
                                    hasPin = true
                                    unlocked = true
                                }
                            }
                            PinStore.remaining(ctx) > 0L -> {
                                message = t("TOO MANY ATTEMPTS")
                                errorState = true
                            }
                            PinStore.verify(ctx, pin) -> unlocked = true
                            else -> {
                                message = if (PinStore.remaining(ctx) > 0L)
                                    t("TOO MANY ATTEMPTS") else t("INCORRECT PIN")
                                errorState = true
                            }
                        }
                    } catch (_: Exception) {
                        message = t("PIN STORAGE ERROR")
                        errorState = true
                    }
                }
            ) { Text(if (!hasPin && first.isEmpty()) t("CONTINUE") else t("CONFIRM")) }
            if (!hasPin && first.isNotEmpty()) {
                TextButton(onClick = { first = ""; typed = ""; message = "" }) {
                    Text(t("START OVER"))
                }
            }
        }
    }
}
