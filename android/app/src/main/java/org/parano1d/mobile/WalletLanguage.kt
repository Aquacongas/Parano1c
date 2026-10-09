package org.parano1d.mobile

import android.content.Context
import android.content.res.Configuration
import androidx.activity.ComponentActivity
import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import java.util.Locale

/** App-specific locale; does not depend on wallet masterkey, node or sync state. */
internal object WalletLanguage {
    private const val PREF = "parano1c_ui_locale_v1"
    private const val KEY = "locale"
    val options = listOf(
        "en" to "English",
        "de" to "Deutsch",
        "fr" to "Français",
        "es" to "Español",
        "pt" to "Português",
        "it" to "Italiano",
        "pl" to "Polski",
        "zh" to "简体中文",
        "zh-TW" to "繁體中文",
        "ja" to "日本語",
        "ko" to "한국어",
        "ru" to "Русский",
        "uk" to "Українська",
        "nl" to "Nederlands",
        "tr" to "Türkçe",
        "id" to "Bahasa Indonesia",
        "hi" to "हिन्दी",
        "ar" to "العربية"
    )
    private fun prefs(context: Context) = context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
    fun selected(context: Context): String? = prefs(context).getString(KEY, null)
    fun set(context: Context, tag: String) {
        require(options.any { it.first == tag })
        prefs(context).edit().putString(KEY, tag).apply()
    }
    fun resourceContext(context: Context): Context {
        val code = selected(context) ?: "en"
        val config = Configuration(context.resources.configuration)
        config.setLocale(Locale.forLanguageTag(code))
        return context.createConfigurationContext(config)
    }
    private lateinit var application: Context
    fun bind(context: Context) { application = context.applicationContext }
    fun uiString(english: String): String {
        if (!::application.isInitialized) return english
        val res = resourceContext(application)
        val name = "p1_ui_" + english.lowercase(java.util.Locale.ROOT)
            .replace(Regex("[^a-z0-9]+"), "_").trim('_').take(65)
        val id = res.resources.getIdentifier(name, "string", res.packageName)
        return if (id != 0) res.getString(id) else english
    }
    fun string(context: Context, resId: Int): String = resourceContext(context).getString(resId)
    fun format(context: Context, resId: Int, vararg args: Any): String =
        resourceContext(context).getString(resId, *args)
}

/** Shown before WalletApp is composed, before any wallet setup/import UI. */
@Composable
internal fun WalletLanguageGate(content: @Composable () -> Unit) {
    val context = LocalContext.current
    WalletLanguage.bind(context)
    var code by remember { mutableStateOf(WalletLanguage.selected(context)) }
    if (code == null) {
        var choice by remember { mutableStateOf("en") }
        val preview = remember(choice) {
            val cfg = Configuration(context.resources.configuration)
            cfg.setLocale(Locale.forLanguageTag(choice))
            context.createConfigurationContext(cfg)
        }
        ParanoTheme {
            Column(
                Modifier.fillMaxSize()
                    .background(ParanoBackground)
                    .safeDrawingPadding()
                    .padding(horizontal = 20.dp, vertical = 12.dp)
            ) {
                Text(
                    preview.getString(R.string.p1_choose_language),
                    style = MaterialTheme.typography.headlineMedium,
                    color = ParanoText
                )
                Spacer(Modifier.height(12.dp))
                Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
                    WalletLanguage.options.forEach { (tag, name) ->
                        Row(
                            Modifier.fillMaxWidth().clickable { choice = tag }
                                .padding(vertical = 7.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = choice == tag,
                                onClick = { choice = tag },
                                colors = RadioButtonDefaults.colors(
                                    selectedColor = ParanoGreen,
                                    unselectedColor = ParanoMuted
                                )
                            )
                            Text(name, color = ParanoText)
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = { WalletLanguage.set(context, choice); code = choice },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = ParanoGreen,
                        contentColor = ParanoBackground
                    )
                ) {
                    Text(preview.getString(R.string.p1_continue_language))
                }
            }
        }
    } else content()
}

/** Settings control: app locale is changed without wiping data or restarting P2P. */
@Composable
internal fun WalletLanguageSetting() {
    val context = LocalContext.current
    var selected by remember { mutableStateOf(WalletLanguage.selected(context) ?: "en") }
    var show by remember { mutableStateOf(false) }
    OutlinedButton(onClick = { show = true }) {
        Text(WalletLanguage.string(context, R.string.p1_language_label) + ": " +
            (WalletLanguage.options.find { it.first == selected }?.second ?: "English"))
    }
    if (show) AlertDialog(
        onDismissRequest = { show = false },
        title = { Text(WalletLanguage.string(context, R.string.p1_change_language)) },
        text = {
            Column(Modifier.heightIn(max = 400.dp).verticalScroll(rememberScrollState())) {
                WalletLanguage.options.forEach { (tag, name) ->
                    TextButton(onClick = {
                        WalletLanguage.set(context, tag)
                        selected = tag
                        show = false
                        (context as? ComponentActivity)?.recreate()
                    }) { Text(name) }
                }
            }
        },
        confirmButton = { TextButton(onClick = { show = false }) { Text("OK") } }
    )
}
