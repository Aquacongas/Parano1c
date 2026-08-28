
package org.parano1d.mobile

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val ParanoBackground =
    Color(0xFF0B0E16)

val ParanoSurface =
    Color(0xFF1E2230)

val ParanoSurfaceAlt =
    Color(0xFF252A3A)

val ParanoBorder =
    Color(0xFF343A4D)

val ParanoGreen =
    Color(0xFF39E67A)

val ParanoCyan =
    Color(0xFF55D8F5)

val ParanoMagenta =
    Color(0xFFD455D9)

val ParanoYellow =
    Color(0xFFF1DF3A)

val ParanoText =
    Color(0xFFF0F0F4)

val ParanoMuted =
    Color(0xFF9296A7)

val ParanoDanger =
    Color(0xFFFF5A68)


private val ParanoColorScheme =
    darkColorScheme(
        primary = ParanoGreen,
        secondary = ParanoCyan,
        tertiary = ParanoMagenta,

        background = ParanoBackground,
        surface = ParanoSurface,

        onPrimary = ParanoBackground,
        onBackground = ParanoText,
        onSurface = ParanoText,

        error = ParanoDanger
    )


@Composable
fun ParanoTheme(
    content: @Composable () -> Unit
) {

    MaterialTheme(
        colorScheme =
            ParanoColorScheme,

        content = content
    )
}
