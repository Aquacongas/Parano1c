package org.parano1d.mobile

import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.clickable
import androidx.compose.animation.core.tween
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.LinearEasing
import android.net.Uri
import android.content.Intent
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.foundation.text.KeyboardOptions
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val Bg =
    Color(0xFF0B0E16)

private val Surface =
    Color(0xFF1E2230)

private val Surface2 =
    Color(0xFF252A3A)

private val Border =
    Color(0xFF343A4D)

private val Green =
    Color(0xFF39E67A)

private val Cyan =
    Color(0xFF55D8F5)

private val Magenta =
    Color(0xFFD455D9)

private val Yellow =
    Color(0xFFF1DF3A)

private val TextMain =
    Color(0xFFF0F0F4)

private val Muted =
    Color(0xFF9296A7)

private val Danger =
    Color(0xFFFF5A68)

private val Mono =
    FontFamily.Monospace

private enum class AppScreen {
    Loading,
    Setup,
    Wallet,
    Addresses,
    Transactions,
    Settings
}


@Composable
private fun WalletInputColors() =
    OutlinedTextFieldDefaults.colors(
        focusedTextColor = Color(0xFFF4F7FB),
        unfocusedTextColor = Color(0xFFF4F7FB),
        disabledTextColor = Color(0xFF8F99AA),

        cursorColor = Green,

        focusedBorderColor = Green,
        unfocusedBorderColor = Color(0xFF657087),
        disabledBorderColor = Color(0xFF404858),

        focusedLabelColor = Green,
        unfocusedLabelColor = Color(0xFFC8D0DC),
        disabledLabelColor = Color(0xFF7E8899),

        focusedPlaceholderColor = Color(0xFFAAB3C2),
        unfocusedPlaceholderColor = Color(0xFFAAB3C2),

        focusedContainerColor = Color.Transparent,
        unfocusedContainerColor = Color.Transparent,
        disabledContainerColor = Color.Transparent
    )

@Composable
fun WalletApp() {
    WalletApp(
        context =
            LocalContext.current
    )
}

@Composable
fun WalletApp(
    context: Context
) {
    val controller =
        remember {
            WalletController(
                context.applicationContext
            )
        }

    var screen by remember {
        mutableStateOf(
            AppScreen.Loading
        )
    }

    var node by remember {
        mutableStateOf(
            NodeStatus()
        )
    }

    var wallet by remember {
        mutableStateOf(
            WalletInfo()
        )
    }

    var overview by remember {
        mutableStateOf(
            WalletOverview()
        )
    }

    var recentTransactions by remember {
        mutableStateOf(emptyList<RecentTransaction>())
    }
    var transactionLimit by remember { mutableStateOf(100) }
    var transactionLoading by remember { mutableStateOf(false) }

    var startupError by remember {
        mutableStateOf<String?>(null)
    }

    var operationError by remember {
        mutableStateOf<String?>(null)
    }

    var busy by remember {
        mutableStateOf(false)
    }

    var pendingSendDestination by remember {
        mutableStateOf<String?>(null)
    }

    suspend fun startNode() {
        busy = true
        startupError = null

        val result =
            withContext(
                Dispatchers.IO
            ) {
                try {
                    NodeSyncService.start(context.applicationContext)
                    NativeResult(ok = true)
                } catch (error: Exception) {
                    NativeResult(ok = false, error = error.message)
                }
            }

        if (!result.ok) {
            startupError =
                result.error
                    ?: WalletLanguage.uiString("Node start failed")
        }

        node =
            withContext(
                Dispatchers.IO
            ) {
                controller.status()
            }

        wallet =
            withContext(
                Dispatchers.IO
            ) {
                controller.wallet()
            }

        busy = false
    }

    LaunchedEffect(Unit) {
        val splashStartedAt =
            System.currentTimeMillis()

        val configured =
            try {
                withContext(
                    Dispatchers.IO
                ) {
                    controller
                        .walletConfigured()
                }
            } catch (
                error: Throwable
            ) {
                operationError =
                    error.message
                        ?: error.javaClass.simpleName

                false
            }

        // Start the real node while the branded splash is still visible.
        // The splash is a presentation layer, not a five-second startup stall.
        if (configured) {
            startNode()
        }

        val elapsed =
            System.currentTimeMillis() -
                splashStartedAt

        val remaining =
            (5000L - elapsed)
                .coerceAtLeast(0L)

        if (remaining > 0L) {
            delay(remaining)
        }

        screen =
            if (configured)
                AppScreen.Wallet
            else
                AppScreen.Setup
    }

    LaunchedEffect(screen, transactionLimit) {
        if (
            screen == AppScreen.Wallet ||
            screen == AppScreen.Settings ||
            screen == AppScreen.Transactions
        ) {
            while (true) {
                node =
                    withContext(
                        Dispatchers.IO
                    ) {
                        controller.status()
                    }

                wallet =
                    withContext(
                        Dispatchers.IO
                    ) {
                        controller.wallet()
                    }

                overview =
                    withContext(
                        Dispatchers.IO
                    ) {
                        controller.walletOverview()
                    }

                if (screen == AppScreen.Transactions) {
                    transactionLoading = true
                    try {
                        recentTransactions = withContext(Dispatchers.IO) {
                            controller.recentTransactions(transactionLimit)
                        }
                    } finally {
                        transactionLoading = false
                    }
                }

                delay(1500)
            }
        }
    }

    when (screen) {

        AppScreen.Loading ->
            LoadingScreen()

        AppScreen.Setup ->
            SetupScreen(
                busy = busy,

                error =
                    operationError,

                onCreate = {
                    busy = true
                    operationError = null

                    MainScope()
                        .launch {
                            val result =
                                withContext(
                                    Dispatchers.IO
                                ) {
                                    controller
                                        .createWallet()
                                }

                            if (result.ok) {
                                screen =
                                    AppScreen.Wallet

                                startNode()
                            } else {
                                operationError =
                                    result.error
                            }

                            busy = false
                        }
                },

                onImport = {
                    masterKey ->

                    busy = true
                    operationError = null

                    MainScope()
                        .launch {
                            val result =
                                withContext(
                                    Dispatchers.IO
                                ) {
                                    controller
                                        .importWallet(
                                            masterKey
                                        )
                                }

                            if (result.ok) {
                                screen =
                                    AppScreen.Wallet

                                startNode()
                            } else {
                                operationError =
                                    result.error
                            }

                            busy = false
                        }
                }
            )

        AppScreen.Wallet ->
            WalletHome(
                context = context,
                controller = controller,
                node = node,
                overview = overview,
                startupError = startupError,
                initialSendDestination =
                    pendingSendDestination,

                onSendDestinationConsumed = {
                    pendingSendDestination = null
                },

                onAddresses = {
                    screen =
                        AppScreen.Addresses
                },

                onSettings = {
                    screen =
                        AppScreen.Settings
                },
                onTransactions = {
                    transactionLimit = 100
                    screen = AppScreen.Transactions
                }
            )

        AppScreen.Transactions ->
            TransactionsScreen(
                context = context,
                controller = controller,
                transactions = recentTransactions,
                loading = transactionLoading,
                limit = transactionLimit,
                onLoadMore = { transactionLimit = (transactionLimit + 100).coerceAtMost(5000) },
                onBack = { screen = AppScreen.Wallet }
            )

        AppScreen.Addresses ->
            AddressesScreen(
                overview = overview,

                onBack = {
                    screen =
                        AppScreen.Wallet
                },

                onNewAddress = {
                    kotlinx.coroutines.MainScope()
                        .launch {
                            overview =
                                withContext(
                                    Dispatchers.IO
                                ) {
                                    controller
                                        .newAddress()
                                }
                        }
                },

                onSelectAddress = {
                    keyIndex ->

                    kotlinx.coroutines.MainScope()
                        .launch {
                            overview =
                                withContext(
                                    Dispatchers.IO
                                ) {
                                    controller
                                        .setActiveAddress(
                                            keyIndex
                                        )
                                }

                            if (
                                overview.error == null
                            ) {
                                screen =
                                    AppScreen.Wallet
                            }
                        }
                }
            )

        AppScreen.Settings ->
            SettingsScreen(
                context = context,
                controller = controller,
                node = node,
                wallet = wallet,

                onBack = {
                    screen =
                        AppScreen.Wallet
                },

                onDonate = {
                    pendingSendDestination =
                        "o1pgeng7j7f0aeuwpvrtf4qhkttddkr4xlyhjkjdz0d9rrt859md3sa9zhnn"

                    screen =
                        AppScreen.Wallet
                },

                onDeleted = {
                    node =
                        NodeStatus()

                    wallet =
                        WalletInfo()

                    startupError = null
                    operationError = null

                    screen =
                        AppScreen.Setup
                }
            )
    }
}

@Composable
private fun LoadingScreen() {
    val transition =
        rememberInfiniteTransition(
            label = "wallet-splash"
        )

    val progress by
        transition.animateFloat(
            initialValue = 0f,
            targetValue = 1f,
            animationSpec =
                infiniteRepeatable(
                    animation =
                        tween(
                            durationMillis = 1350,
                            easing =
                                LinearEasing
                        ),
                    repeatMode =
                        RepeatMode.Restart
                ),
            label = "wallet-splash-progress"
        )

    Box(
        modifier =
            Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .background(Bg)
                .padding(24.dp)
    ) {
        Row(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .align(
                        Alignment.TopCenter
                    ),
            verticalAlignment =
                Alignment.CenterVertically
        ) {
            Box(
                modifier =
                    Modifier
                        .width(6.dp)
                        .height(6.dp)
                        .background(
                            Green,
                            RoundedCornerShape(50)
                        )
            )

            Spacer(
                Modifier.width(9.dp)
            )

            Text(
                WalletLanguage.uiString("PARANO1D / MAINNET / MOBILE"),
                color = Muted,
                fontFamily = Mono,
                fontSize = 9.sp,
                letterSpacing = 1.sp
            )
        }

        Column(
            modifier =
                Modifier.align(
                    Alignment.Center
                ),
            horizontalAlignment =
                Alignment.CenterHorizontally
        ) {
            Logo(
                size = 38,
                centered = true
            )

            Spacer(
                Modifier.height(10.dp)
            )

            Text(
                WalletLanguage.uiString("FULL MOBILE WALLET"),
                color = Cyan,
                fontFamily = Mono,
                fontSize = 12.sp,
                fontWeight =
                    FontWeight.Bold,
                letterSpacing = 2.sp
            )

            Spacer(
                Modifier.height(38.dp)
            )

            Box(
                modifier =
                    Modifier
                        .width(224.dp)
                        .height(4.dp)
                        .background(
                            Border,
                            RoundedCornerShape(50)
                        )
            ) {
                // 60dp segment moving across a 224dp track.
                Box(
                    modifier =
                        Modifier
                            .offset(
                                x =
                                    (164f * progress)
                                        .dp
                            )
                            .width(60.dp)
                            .height(4.dp)
                            .background(
                                Green,
                                RoundedCornerShape(50)
                            )
                )
            }

            Spacer(
                Modifier.height(14.dp)
            )

            Text(
                WalletLanguage.uiString("INITIALIZING WALLET + FULL NODE"),
                color = Muted,
                fontFamily = Mono,
                fontSize = 9.sp,
                letterSpacing = 1.sp
            )
        }

        Column(
            modifier =
                Modifier
                    .align(
                        Alignment.BottomCenter
                    )
                    .padding(
                        bottom = 12.dp
                    ),
            horizontalAlignment =
                Alignment.CenterHorizontally
        ) {
            Text(
                WalletLanguage.uiString("FULL NODE WALLET  •  MAINNET"),
                color = Magenta,
                fontFamily = Mono,
                fontSize = 9.sp,
                letterSpacing = 1.sp
            )

            Spacer(
                Modifier.height(7.dp)
            )

            Text(
                WalletLanguage.uiString("Made by Aquacongas"),
                color = Muted,
                fontFamily = Mono,
                fontSize = 10.sp
            )
        }
    }
}

@Composable
private fun Logo(
    size: Int = 32,
    centered: Boolean = false
) {
    Row(
        modifier =
            if (centered)
                Modifier
            else
                Modifier,
        verticalAlignment =
            Alignment.CenterVertically
    ) {
        Text(
            "Paran",
            color = TextMain,
            fontFamily = Mono,
            fontWeight =
                FontWeight.Bold,
            fontSize = size.sp
        )

        Text(
            "O(1)c",
            color = Green,
            fontFamily = Mono,
            fontWeight =
                FontWeight.Bold,
            fontSize = size.sp
        )
    }
}


@Composable
private fun SetupScreen(
    busy: Boolean,
    error: String?,
    onCreate: () -> Unit,
    onImport: (String) -> Unit
) {
    var importDialog by remember {
        mutableStateOf(false)
    }

    var masterKey by remember {
        mutableStateOf("")
    }

    Column(
        modifier =
            Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .background(Bg)
                .padding(22.dp),

        horizontalAlignment =
            Alignment.CenterHorizontally,

        verticalArrangement =
            Arrangement.Center
    ) {
        Logo()

        Spacer(
            Modifier.height(8.dp)
        )

        Text(
            WalletLanguage.uiString("FULL MOBILE WALLET"),
            color = Cyan,
            fontFamily = Mono,
            fontSize = 12.sp,
            letterSpacing = 2.sp
        )

        Spacer(
            Modifier.height(40.dp)
        )

        TerminalCard {
            Text(
                WalletLanguage.uiString("WALLET SETUP"),
                color = Green,
                fontFamily = Mono,
                fontWeight =
                    FontWeight.Bold,
                fontSize = 14.sp
            )

            Spacer(
                Modifier.height(10.dp)
            )

            Text(
                WalletLanguage.uiString("No configured wallet found."),
                color = Muted,
                fontFamily = Mono,
                fontSize = 12.sp
            )

            Spacer(
                Modifier.height(24.dp)
            )

            ActionButton(
                text =
                    WalletLanguage.uiString("CREATE NEW WALLET"),
                enabled =
                    !busy,
                onClick =
                    onCreate
            )

            Spacer(
                Modifier.height(12.dp)
            )

            ActionButton(
                text =
                    WalletLanguage.uiString("IMPORT WALLET"),
                enabled =
                    !busy,
                onClick = {
                    importDialog = true
                }
            )

            if (busy) {
                Spacer(
                    Modifier.height(18.dp)
                )

                Text(
                    WalletLanguage.uiString("WORKING..."),
                    color = Yellow,
                    fontFamily = Mono,
                    fontSize = 11.sp
                )
            }

            if (!error.isNullOrBlank()) {
                Spacer(
                    Modifier.height(18.dp)
                )

                ErrorText(error)
            }
        }
    }

    if (importDialog) {
        AlertDialog(
            onDismissRequest = {
                if (!busy) {
                    importDialog = false
                }
            },

            containerColor =
                Surface,

            title = {
                Text(
                    WalletLanguage.uiString("IMPORT WALLET"),
                    color = Green,
                    fontFamily = Mono
                )
            },

            text = {
                Column {
                    Text(
                        WalletLanguage.uiString("Enter the 64-character hexadecimal master key."),
                        color = Muted,
                        fontFamily = Mono,
                        fontSize = 12.sp
                    )

                    Spacer(
                        Modifier.height(12.dp)
                    )

                    OutlinedTextField(
                        value =
                            masterKey,

                        onValueChange = {
                            masterKey =
                                it
                                    .filterNot(
                                        Char::isWhitespace
                                    )
                                    .take(64)
                        },

                        label = {
                            Text(
                                WalletLanguage.uiString("MASTER KEY")
                            )
                        },

                        visualTransformation =
                            PasswordVisualTransformation(),

                        singleLine = true,
                        colors =
                            WalletInputColors()
                    )
                }
            },

            confirmButton = {
                TextButton(
                    enabled =
                        !busy &&
                        masterKey.length == 64,

                    onClick = {
                        importDialog = false

                        onImport(
                            masterKey
                        )

                        masterKey = ""
                    }
                ) {
                    Text(
                        WalletLanguage.uiString("IMPORT"),
                        color = Green
                    )
                }
            },

            dismissButton = {
                TextButton(
                    onClick = {
                        masterKey = ""
                        importDialog = false
                    }
                ) {
                    Text(
                        WalletLanguage.uiString("CANCEL"),
                        color = Muted
                    )
                }
            }
        )
    }
}

@Composable
private fun WalletHome(
    context: Context,
    controller: WalletController,
    node: NodeStatus,
    overview: WalletOverview,
    startupError: String?,
    initialSendDestination: String?,
    onSendDestinationConsumed: () -> Unit,
    onAddresses: () -> Unit,
    onSettings: () -> Unit,
    onTransactions: () -> Unit
) {
    var sendDialog by remember {
        mutableStateOf(false)
    }

    var receiveDialog by remember {
        mutableStateOf(false)
    }

    LaunchedEffect(
        initialSendDestination
    ) {
        if (
            !initialSendDestination
                .isNullOrBlank()
        ) {
            sendDialog = true
        }
    }

    val active =
        overview.activeAddress

    Column(
        modifier =
            Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .background(Bg)
                .verticalScroll(
                    rememberScrollState()
                )
                .padding(
                    horizontal = 10.dp,
                    vertical = 10.dp
                )
    ) {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .background(
                        Surface,
                        RoundedCornerShape(
                            18.dp
                        )
                    )
                    .border(
                        1.dp,
                        Border,
                        RoundedCornerShape(
                            18.dp
                        )
                    )
        ) {
            Row(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .background(
                            Surface2,
                            RoundedCornerShape(
                                topStart = 18.dp,
                                topEnd = 18.dp
                            )
                        )
                        .padding(
                            horizontal = 16.dp,
                            vertical = 17.dp
                        ),
                verticalAlignment =
                    Alignment.CenterVertically
            ) {
                Box(
                    modifier =
                        Modifier
                            .width(7.dp)
                            .height(7.dp)
                            .background(
                                Green,
                                RoundedCornerShape(50)
                            )
                )

                Spacer(
                    Modifier.width(10.dp)
                )

                Logo(
                    size = 27
                )
            }

            NodeCard(
                node = node
            )

            Column(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .padding(
                            horizontal = 16.dp,
                            vertical = 20.dp
                        )
            ) {
                Text(
                    WalletLanguage.uiString("AVAILABLE BALANCE"),
                    color = Cyan,
                    fontFamily = Mono,
                    fontSize = 10.sp,
                    letterSpacing = 1.sp
                )

                Spacer(
                    Modifier.height(8.dp)
                )

                Row(
                    verticalAlignment =
                        Alignment.Bottom
                ) {
                    Text(
                        WalletController
                            .formatNoid(
                                overview
                                    .availableBalanceMicronoid
                            ),
                        color = TextMain,
                        fontFamily = Mono,
                        fontSize = 41.sp,
                        fontWeight =
                            FontWeight.Bold
                    )

                    Spacer(
                        Modifier.width(9.dp)
                    )

                    Text(
                        "NOID",
                        color = Green,
                        fontFamily = Mono,
                        fontSize = 16.sp,
                        fontWeight =
                            FontWeight.Bold
                    )
                }

                Spacer(Modifier.height(5.dp))

                Text(
                    WalletLanguage.uiString("FROM ALL ADDRESSES"),
                    color = Muted,
                    fontFamily = Mono,
                    fontSize = 10.sp
                )

                Spacer(
                    Modifier.height(24.dp)
                )

                Column(
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .background(
                                Surface2,
                                RoundedCornerShape(
                                    14.dp
                                )
                            )
                            .border(
                                1.dp,
                                Border,
                                RoundedCornerShape(
                                    14.dp
                                )
                            )
                            .padding(16.dp)
                ) {
                    Row(
                        modifier =
                            Modifier.fillMaxWidth(),
                        verticalAlignment =
                            Alignment.CenterVertically
                    ) {
                        Column(
                            modifier =
                                Modifier.weight(1f)
                        ) {
                            Text(
                                WalletLanguage.uiString("ACTIVE ADDRESS"),
                                color = Magenta,
                                fontFamily = Mono,
                                fontSize = 9.sp,
                                letterSpacing = 1.sp
                            )

                            Spacer(
                                Modifier.height(4.dp)
                            )

                            Text(
                                "#${overview.activeIndex}",
                                color = Green,
                                fontFamily = Mono,
                                fontSize = 15.sp,
                                fontWeight =
                                    FontWeight.Bold
                            )
                        }

                        CompactOutlineButton(
                            text = WalletLanguage.uiString("CHANGE"),
                            accent = Green,
                            onClick =
                                onAddresses
                        )
                    }

                    Spacer(
                        Modifier.height(14.dp)
                    )

                    Text(
                        active?.address ?: "—",
                        color = TextMain,
                        fontFamily = Mono,
                        fontSize = 11.sp
                    )

                    Spacer(
                        Modifier.height(18.dp)
                    )

                    HorizontalDivider(
                        color = Border
                    )

                    Spacer(
                        Modifier.height(14.dp)
                    )

                    Row(
                        modifier =
                            Modifier.fillMaxWidth(),
                        verticalAlignment =
                            Alignment.Bottom
                    ) {
                        Column {
                            Text(
                                WalletLanguage.uiString("ACTIVE BALANCE"),
                                color = Muted,
                                fontFamily = Mono,
                                fontSize = 9.sp
                            )

                            Spacer(
                                Modifier.height(4.dp)
                            )

                            Text(
                                WalletController
                                    .formatNoid(
                                        overview
                                            .activeBalanceMicronoid
                                    ),
                                color = Cyan,
                                fontFamily = Mono,
                                fontSize = 24.sp,
                                fontWeight =
                                    FontWeight.Bold
                            )
                        }

                        Spacer(
                            Modifier.weight(1f)
                        )

                        Text(
                            "NOID",
                            color = Muted,
                            fontFamily = Mono,
                            fontSize = 10.sp
                        )
                    }
                }

                Spacer(
                    Modifier.height(18.dp)
                )

                Row(
                    modifier =
                        Modifier.fillMaxWidth(),
                    horizontalArrangement =
                        Arrangement.spacedBy(
                            10.dp
                        )
                ) {
                    Box(
                        modifier =
                            Modifier.weight(1f)
                    ) {
                        ActionButton(
                            text = WalletLanguage.uiString("SEND"),
                            enabled =
                                active != null,
                            onClick = {
                                sendDialog = true
                            }
                        )
                    }

                    Box(
                        modifier =
                            Modifier.weight(1f)
                    ) {
                        AccentButton(
                            text = WalletLanguage.uiString("RECEIVE"),
                            accent = Cyan,
                            enabled =
                                active != null,
                            onClick = {
                                receiveDialog = true
                            }
                        )
                    }
                }

                Spacer(
                    Modifier.height(10.dp)
                )

                OutlineActionButton(
                    text = WalletLanguage.uiString("SETTINGS"),
                    accent = Cyan,
                    onClick =
                        onSettings
                )

                Spacer(
                    Modifier.height(10.dp)
                )

                OutlineActionButton(
                    text = WalletLanguage.uiString("TRANSACTIONS"),
                    accent = Cyan,
                    onClick = onTransactions
                )
            }
        }

        if (
            !startupError.isNullOrBlank() &&
            !startupError.equals(
                "mobile node already running",
                ignoreCase = true
            )
        ) {
            Spacer(
                Modifier.height(10.dp)
            )

            ErrorText(
                startupError
            )
        }

        Spacer(
            Modifier.height(12.dp)
        )
    }

    if (sendDialog) {
        SendDialog(
            controller = controller,
            initialDestination =
                initialSendDestination
                    .orEmpty(),
            onDismiss = {
                sendDialog = false

                if (
                    !initialSendDestination
                        .isNullOrBlank()
                ) {
                    onSendDestinationConsumed()
                }
            }
        )
    }

    if (
        receiveDialog &&
        active != null
    ) {
        ReceiveDialog(
            context = context,
            address = active.address,
            onDismiss = {
                receiveDialog = false
            }
        )
    }
}

@Composable
private fun AddressesScreen(
    overview: WalletOverview,
    onBack: () -> Unit,
    onNewAddress: () -> Unit,
    onSelectAddress: (Int) -> Unit
) {
    Column(
        modifier =
            Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .background(Bg)
                .verticalScroll(
                    rememberScrollState()
                )
                .padding(
                    horizontal = 20.dp,
                    vertical = 18.dp
                )
    ) {

        Row(
            modifier =
                Modifier.fillMaxWidth(),

            verticalAlignment =
                Alignment.CenterVertically
        ) {

            TextButton(
                onClick =
                    onBack
            ) {
                Text(
                    WalletLanguage.uiString("BACK"),
                    color = Cyan,
                    fontSize = 12.sp
                )
            }

            Spacer(
                Modifier.weight(1f)
            )

            Text(
                WalletLanguage.uiString("ADDRESSES"),
                color = TextMain,
                fontSize = 20.sp,
                fontWeight =
                    FontWeight.Bold
            )
        }

        Spacer(
            Modifier.height(22.dp)
        )

        Text(WalletLanguage.uiString("GENERATED").let { "${overview.addressCount} $it" },
            color = Muted,
            fontSize = 11.sp
        )

        Spacer(
            Modifier.height(14.dp)
        )

        overview.addresses.forEach {
            item ->

            Column(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .background(
                            Surface,
                            RoundedCornerShape(
                                16.dp
                            )
                        )
                        .border(
                            width = 1.dp,

                            color =
                                if (item.active)
                                    Green
                                else
                                    Border,

                            shape =
                                RoundedCornerShape(
                                    16.dp
                                )
                        )
                        .padding(16.dp)
            ) {

                Row(
                    modifier =
                        Modifier.fillMaxWidth(),

                    verticalAlignment =
                        Alignment.CenterVertically
                ) {

                    Text(
                        "#${item.keyIndex}",
                        color =
                            if (item.active)
                                Green
                            else
                                TextMain,

                        fontSize = 15.sp,

                        fontWeight =
                            FontWeight.Bold
                    )

                    Spacer(
                        Modifier.weight(1f)
                    )

                    if (item.active) {

                        Text(
                            WalletLanguage.uiString("ACTIVE"),
                            color = Green,
                            fontSize = 11.sp,
                            fontWeight =
                                FontWeight.Bold
                        )

                    } else {

                        TextButton(
                            onClick = {
                                onSelectAddress(
                                    item.keyIndex
                                )
                            }
                        ) {
                            Text(
                                WalletLanguage.uiString("SELECT"),
                                color = Cyan,
                                fontSize = 11.sp,
                                fontWeight =
                                    FontWeight.Bold
                            )
                        }
                    }
                }

                Spacer(
                    Modifier.height(8.dp)
                )

                Text(
                    item.address,
                    color = Muted,
                    fontSize = 11.sp
                )

                Spacer(
                    Modifier.height(12.dp)
                )

                Text(
                    "${
                        WalletController.formatNoid(
                            item.balanceMicronoid
                        )
                    } NOID",

                    color = TextMain,
                    fontSize = 16.sp,

                    fontWeight =
                        FontWeight.Medium
                )
            }

            Spacer(
                Modifier.height(12.dp)
            )
        }

        Spacer(
            Modifier.height(4.dp)
        )

        ActionButton(
            text =
                WalletLanguage.uiString("NEW ADDRESS"),

            enabled =
                overview.error == null,

            onClick =
                onNewAddress
        )

        if (!overview.error.isNullOrBlank()) {

            Spacer(
                Modifier.height(14.dp)
            )

            Text(
                overview.error,
                color = Danger,
                fontSize = 11.sp
            )
        }

        Spacer(
            Modifier.height(30.dp)
        )
    }
}



@Composable
private fun NodeCard(
    node: NodeStatus
) {
    Column(
        modifier =
            Modifier
                .fillMaxWidth()
    ) {
        Row(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .background(Surface2)
                    .padding(
                        horizontal = 16.dp,
                        vertical = 9.dp
                    ),
            verticalAlignment =
                Alignment.CenterVertically
        ) {
            Text(
                WalletLanguage.uiString("STATUS"),
                color = Cyan,
                fontFamily = Mono,
                fontSize = 9.sp,
                letterSpacing = 1.sp
            )

            Spacer(
                Modifier.width(9.dp)
            )

            Text(
                if (node.running)
                    WalletLanguage.uiString("ONLINE")
                else
                    WalletLanguage.uiString("OFFLINE"),
                color =
                    if (node.running)
                        Green
                    else
                        Danger,
                fontFamily = Mono,
                fontSize = 12.sp,
                fontWeight =
                    FontWeight.Bold
            )

            Spacer(
                Modifier.weight(1f)
            )

            Box(
                modifier =
                    Modifier
                        .width(7.dp)
                        .height(7.dp)
                        .background(
                            if (
                                node.running &&
                                node.peers > 0
                            )
                                Green
                            else
                                Muted,
                            RoundedCornerShape(50)
                        )
            )
        }

        Row(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(
                        start = 16.dp,
                        end = 16.dp,
                        top = 10.dp,
                        bottom = 12.dp
                    ),
            horizontalArrangement =
                Arrangement.spacedBy(
                    10.dp
                )
        ) {
            MetricCell(
                modifier =
                    Modifier.weight(1f),
                label = WalletLanguage.uiString("HEIGHT"),
                value =
                    node.tipHeight
                        .toString(),
                accent =
                    TextMain
            )

            MetricCell(
                modifier =
                    Modifier.weight(1f),
                label = WalletLanguage.uiString("SYNC"),
                value =
                    if (!node.running)
                        WalletLanguage.uiString("OFFLINE")
                    else
                        node.syncState,
                accent =
                    if (
                        node.running &&
                        node.peers > 0
                    )
                        Cyan
                    else
                        Muted
            )

            MetricCell(
                modifier =
                    Modifier.weight(1f),
                label = WalletLanguage.uiString("PEERS"),
                value =
                    node.peers
                        .toString(),
                accent =
                    if (node.peers > 0)
                        Green
                    else
                        Muted
            )
        }

        HorizontalDivider(
            color = Border
        )
    }
}

@Composable
private fun TransactionsScreen(
    context: Context,
    controller: WalletController,
    transactions: List<RecentTransaction>,
    loading: Boolean,
    limit: Int,
    onLoadMore: () -> Unit,
    onBack: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxSize().background(Bg).safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 18.dp, vertical = 14.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            CompactOutlineButton(
                text = WalletLanguage.uiString("< BACK"),
                accent = Cyan,
                onClick = onBack
            )
            Spacer(Modifier.weight(1f))
            Logo(size = 20)
        }
        Spacer(Modifier.height(20.dp))
        Text(
            WalletLanguage.uiString("TRANSACTIONS"),
            color = TextMain,
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold
        )
        var importedReceipt by remember { mutableStateOf("") }
        var verificationMessage by remember { mutableStateOf<String?>(null) }
        var verifyingReceipt by remember { mutableStateOf(false) }
        OutlinedTextField(
            value = importedReceipt,
            onValueChange = {
                importedReceipt = it.take(262170)
                verificationMessage = null
            },
            label = { Text(WalletLanguage.uiString("PASTE RECEIPT")) },
            modifier = Modifier.fillMaxWidth(),
            minLines = 2,
            maxLines = 4,
            textStyle = androidx.compose.ui.text.TextStyle(color = TextMain),
            colors = androidx.compose.material3.OutlinedTextFieldDefaults.colors(
                focusedTextColor = TextMain,
                unfocusedTextColor = TextMain,
                cursorColor = Green,
                focusedLabelColor = Green,
                unfocusedLabelColor = TextMain,
                focusedBorderColor = Green,
                unfocusedBorderColor = TextMain
            )
        )
        Spacer(Modifier.height(8.dp))
        OutlineActionButton(
            text = WalletLanguage.uiString("VERIFY RECEIPT"),
            accent = Cyan,
            onClick = {
                if (!verifyingReceipt && importedReceipt.isNotBlank()) {
                    verifyingReceipt = true
                    MainScope().launch {
                        try {
                            val result = withContext(Dispatchers.IO) {
                                controller.verifyReceiptHex(importedReceipt)
                            }
                            verificationMessage = when {
                                !result.optBoolean("ok") -> result.optString("error", WalletLanguage.uiString("INVALID RECEIPT"))
                                result.optBoolean("canonical_verified") ->
                                    WalletLanguage.uiString("CANONICAL RECEIPT VERIFIED") + "\nTXID: " + result.optString("txid")
                                else -> WalletLanguage.uiString("MERKLE VERIFIED ONLY") + "\n" +
                                    WalletLanguage.uiString("CANONICAL HEADER UNAVAILABLE") + "\nTXID: " + result.optString("txid")
                            }
                        } catch (e: Exception) {
                            verificationMessage = e.message ?: WalletLanguage.uiString("INVALID RECEIPT")
                        } finally { verifyingReceipt = false }
                    }
                }
            }
        )
        if (verificationMessage != null) {
            val message = verificationMessage.orEmpty()
            val canonical = message.startsWith(
                WalletLanguage.uiString("CANONICAL RECEIPT VERIFIED")
            )
            val merkleOnly = message.startsWith(
                WalletLanguage.uiString("MERKLE VERIFIED ONLY")
            )
            val statusColor = when {
                canonical -> Green
                merkleOnly -> Cyan
                else -> androidx.compose.ui.graphics.Color(0xFFFF7070)
            }

            androidx.compose.material3.Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = Surface,
                border = androidx.compose.foundation.BorderStroke(
                    1.dp,
                    statusColor.copy(alpha = 0.65f)
                )
            ) {
                Text(
                    text = message,
                    color = statusColor,
                    fontFamily = Mono,
                    modifier = Modifier.padding(16.dp)
                )
            }
        }
        Spacer(Modifier.height(14.dp))
        if (loading && transactions.isEmpty()) {
            CircularProgressIndicator(color = Cyan)
        }
        RecentTransactionsCard(
            context = context,
            controller = controller,
            transactions = transactions
        )
        Spacer(Modifier.height(12.dp))
        if (transactions.size >= limit && limit < 5000) {
            OutlineActionButton(
                text = WalletLanguage.uiString("LOAD MORE"),
                accent = Cyan,
                onClick = onLoadMore
            )
        }
        if (loading) {
            Spacer(Modifier.height(8.dp))
            CircularProgressIndicator(color = Cyan)
        }
    }
}

@Composable
private fun RecentTransactionsCard(
    context: Context,
    controller: WalletController,
    transactions: List<RecentTransaction>
) {
    var receiptStatus by remember { mutableStateOf<String?>(null) }
    var receiptPayload by remember { mutableStateOf<String?>(null) }
    var receiptBusy by remember { mutableStateOf(false) }
    if (receiptStatus != null) {
        AlertDialog(
            onDismissRequest = { receiptStatus = null },
            title = { Text(WalletLanguage.uiString("PAYMENT RECEIPT")) },
            text = { Text(receiptStatus ?: "") },
            confirmButton = {
                TextButton(
                    enabled = receiptPayload != null,
                    onClick = {
                        val share = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_TEXT, receiptPayload)
                        }
                        context.startActivity(Intent.createChooser(share, null))
                    }
                ) { Text(WalletLanguage.uiString("SHARE RECEIPT")) }
            },
            dismissButton = {
                TextButton(onClick = { receiptStatus = null }) {
                    Text(WalletLanguage.uiString("CLOSE"))
                }
            }
        )
    }
    Column(
        modifier =
            Modifier
                .fillMaxWidth()
                .background(
                    Surface,
                    RoundedCornerShape(
                        14.dp
                    )
                )
                .border(
                    1.dp,
                    Border,
                    RoundedCornerShape(
                        14.dp
                    )
                )
                .padding(14.dp)
    ) {
        Row(
            modifier =
                Modifier.fillMaxWidth(),
            verticalAlignment =
                Alignment.CenterVertically
        ) {
            Text(
                WalletLanguage.uiString("TRANSACTIONS"),
                color = Cyan,
                fontFamily = Mono,
                fontSize = 10.sp,
                fontWeight =
                    FontWeight.Bold,
                letterSpacing = 1.sp
            )

            Spacer(
                Modifier.weight(1f)
            )

            Text(
                transactions.size.toString(),
                color = Muted,
                fontFamily = Mono,
                fontSize = 9.sp
            )
        }

        Spacer(
            Modifier.height(10.dp)
        )

        if (transactions.isEmpty()) {
            Text(
                WalletLanguage.uiString("NO TRANSACTIONS YET"),
                color = Muted,
                fontFamily = Mono,
                fontSize = 10.sp
            )
        } else {
            val shown = transactions

            shown.forEachIndexed {
                index,
                tx ->

                val accent =
                    when {
                        tx.coinbase ->
                            Yellow

                        tx.direction ==
                            "RECEIVED" ->
                            Green

                        else ->
                            Magenta
                    }

                Row(
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .clickable {
                                if (
                                    tx.txid
                                        .isNotBlank()
                                ) {
                                    context.startActivity(
                                        Intent(
                                            Intent.ACTION_VIEW,
                                            Uri.parse(
                                                "https://noidexplorer.org/tx/${tx.txid}"
                                            )
                                        )
                                    )
                                }
                            }
                            .padding(
                                vertical = 8.dp
                            ),
                    verticalAlignment =
                        Alignment.CenterVertically
                ) {
                    Column(
                        modifier =
                            Modifier.weight(1f)
                    ) {
                        Row(
                            verticalAlignment =
                                Alignment.CenterVertically
                        ) {
                            Text(
                                if (tx.coinbase)
                                    "REWARD"
                                else
                                    tx.direction,
                                color = accent,
                                fontFamily = Mono,
                                fontSize = 9.sp,
                                fontWeight =
                                    FontWeight.Bold
                            )

                            if (tx.pending) {
                                Spacer(
                                    Modifier.width(7.dp)
                                )

                                Text(
                                    WalletLanguage.uiString("PENDING"),
                                    color = Yellow,
                                    fontFamily = Mono,
                                    fontSize = 8.sp
                                )
                            }
                        }

                        Spacer(
                            Modifier.height(3.dp)
                        )

                        val shortTxid =
                            if (
                                tx.txid.length >
                                18
                            )
                                tx.txid.take(9) +
                                    "…" +
                                    tx.txid.takeLast(7)
                            else
                                tx.txid

                        Text(
                            "$shortTxid  ↗",
                            color = Muted,
                            fontFamily = Mono,
                            fontSize = 9.sp
                        )
                    }

                    Text(
                        "${
                            WalletController
                                .formatNoid(
                                    tx.amountMicronoid
                                )
                        } NOID",
                        color = TextMain,
                        fontFamily = Mono,
                        fontSize = 10.sp,
                        fontWeight =
                            FontWeight.Bold
                    )
                }

                if (tx.direction == "SENT" && !tx.pending && !tx.coinbase) {
                    TextButton(
                        enabled = !receiptBusy,
                        onClick = {
                            receiptBusy = true
                            receiptPayload = null
                            MainScope().launch {
                                try {
                                    val result = withContext(Dispatchers.IO) {
                                        controller.receipt(tx.txid)
                                    }
                                    if (!result.optBoolean("ok", false)) {
                                        receiptStatus = result.optString("error", "Receipt read failed")
                                    } else if (!result.optBoolean("available", false)) {
                                        receiptStatus = WalletLanguage.uiString("RECEIPT NOT AVAILABLE")
                                    } else if (!result.optBoolean("merkle_valid", false)) {
                                        receiptStatus = WalletLanguage.uiString("INVALID RECEIPT")
                                    } else {
                                        val hex = result.getString("receipt_hex")
                                        receiptPayload = "PARANO1D-RECEIPT-V2-HEX:" + hex
                                        val verified = withContext(Dispatchers.IO) {
                                            controller.verifyReceiptHex(receiptPayload ?: "")
                                        }
                                        receiptStatus = when {
                                            verified.optBoolean("canonical_verified") -> WalletLanguage.uiString("CANONICAL RECEIPT VERIFIED")
                                            verified.optBoolean("ok") -> WalletLanguage.uiString("MERKLE VERIFIED ONLY") +
                                                "\n" + WalletLanguage.uiString("CANONICAL HEADER UNAVAILABLE")
                                            else -> verified.optString("error", WalletLanguage.uiString("INVALID RECEIPT"))
                                        } + "\nTXID: " + tx.txid
                                    }
                                } catch (e: Exception) {
                                    receiptStatus = e.message ?: "Receipt error"
                                } finally {
                                    receiptBusy = false
                                }
                            }
                        }
                    ) { Text(WalletLanguage.uiString("PAYMENT RECEIPT"), color = Cyan) }
                }

                if (index < shown.lastIndex) {
                    HorizontalDivider(
                        color = Border
                    )
                }
            }
        }
    }
}

@Composable
private fun SendDialog(
    controller: WalletController,
    initialDestination: String = "",
    onDismiss: () -> Unit
) {
    val context =
        LocalContext.current

    var destination by remember(
        initialDestination
    ) {
        mutableStateOf(
            initialDestination
        )
    }

    var amount by remember {
        mutableStateOf("")
    }

    var fee by remember {
        mutableStateOf("0")
    }

    var working by remember {
        mutableStateOf(false)
    }

    var result by remember {
        mutableStateOf<String?>(null)
    }

    AlertDialog(
        onDismissRequest = {
            if (!working) {
                onDismiss()
            }
        },
        containerColor =
            Surface,
        title = {
            Column {
                AccentLabel(
                    text = WalletLanguage.uiString("SEND"),
                    accent = Green
                )

                Spacer(
                    Modifier.height(10.dp)
                )

                Text(
                    WalletLanguage.uiString("SEND NOID"),
                    color = TextMain,
                    fontFamily = Mono,
                    fontWeight =
                        FontWeight.Bold,
                    fontSize = 19.sp
                )

                Text(
                    WalletLanguage.uiString("Active address only"),
                    color = Muted,
                    fontFamily = Mono,
                    fontSize = 10.sp
                )
            }
        },
        text = {
            Column {
                OutlinedTextField(
                    value = destination,
                    onValueChange = {
                        destination = it
                    },
                    modifier =
                        Modifier.fillMaxWidth(),
                    label = {
                        Text(
                            WalletLanguage.uiString("DESTINATION")
                        )
                    },
                    placeholder = {
                        Text(
                            "o1..."
                        )
                    },
                    singleLine = true,
                    colors =
                        WalletInputColors()
                )

                Spacer(
                    Modifier.height(12.dp)
                )

                OutlinedTextField(
                    value = amount,
                    onValueChange = {
                        value ->

                        amount =
                            value.filter {
                                ch ->

                                ch.isDigit() ||
                                    ch == '.' ||
                                    ch == ','
                            }
                    },
                    modifier =
                        Modifier.fillMaxWidth(),
                    label = {
                        Text(
                            WalletLanguage.uiString("AMOUNT")
                        )
                    },
                    suffix = {
                        Text(
                            "NOID",
                            color = Cyan,
                            fontFamily = Mono
                        )
                    },
                    singleLine = true,
                    keyboardOptions =
                        KeyboardOptions(
                            keyboardType =
                                KeyboardType.Decimal
                        ),
                    colors =
                        WalletInputColors()
                )

                Spacer(
                    Modifier.height(12.dp)
                )

                OutlinedTextField(
                    value = fee,
                    onValueChange = {
                        value ->

                        fee =
                            value.filter {
                                ch ->

                                ch.isDigit() ||
                                    ch == '.' ||
                                    ch == ','
                            }
                    },
                    modifier =
                        Modifier.fillMaxWidth(),
                    label = {
                        Text(
                            WalletLanguage.uiString("FEE / 0 = AUTO")
                        )
                    },
                    suffix = {
                        Text(
                            "NOID",
                            color = Yellow,
                            fontFamily = Mono
                        )
                    },
                    singleLine = true,
                    keyboardOptions =
                        KeyboardOptions(
                            keyboardType =
                                KeyboardType.Decimal
                        ),
                    colors =
                        WalletInputColors()
                )

                Spacer(
                    Modifier.height(10.dp)
                )

                OutlineActionButton(
                    text =
                        if (working)
                            WalletLanguage.uiString("WORKING...")
                        else
                            WalletLanguage.uiString("SEND ALL"),
                    accent = Magenta,
                    enabled =
                        !working &&
                        destination.isNotBlank(),
                    onClick = {
                        working = true
                        result = null

                        MainScope()
                            .launch {
                                val response =
                                    withContext(
                                        Dispatchers.IO
                                    ) {
                                        controller
                                            .sendAll(
                                                destination
                                            )
                                    }

                                result =
                                    if (response.ok)
                                        "TX ${response.txid}"
                                    else
                                        response.error
                                            ?: WalletLanguage.uiString("SEND ALL failed")

                                working = false
                            }
                    }
                )

                Spacer(
                    Modifier.height(5.dp)
                )

                Text(
                    WalletLanguage.uiString("FULL ACTIVE-ADDRESS BALANCE • AUTO FEE • NO CHANGE"),
                    color = Muted,
                    fontFamily = Mono,
                    fontSize = 8.sp
                )

                if (!result.isNullOrBlank()) {
                    Spacer(
                        Modifier.height(14.dp)
                    )

                    val txSuccess =
                        result!!
                            .startsWith(
                                "TX "
                            )

                    val txid =
                        if (txSuccess)
                            result!!
                                .removePrefix(
                                    "TX "
                                )
                                .trim()
                        else
                            ""

                    Column(
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .background(
                                    Surface2,
                                    RoundedCornerShape(
                                        10.dp
                                    )
                                )
                                .border(
                                    1.dp,
                                    if (txSuccess)
                                        Green
                                    else
                                        Danger,
                                    RoundedCornerShape(
                                        10.dp
                                    )
                                )
                                .then(
                                    if (txSuccess)
                                        Modifier.clickable {
                                            context.startActivity(
                                                Intent(
                                                    Intent.ACTION_VIEW,
                                                    Uri.parse(
                                                        "https://noidexplorer.org/tx/$txid"
                                                    )
                                                )
                                            )
                                        }
                                    else
                                        Modifier
                                )
                                .padding(12.dp)
                    ) {
                        Text(
                            if (txSuccess)
                                "TXID"
                            else
                                "ERROR",
                            color =
                                if (txSuccess)
                                    Green
                                else
                                    Danger,
                            fontFamily = Mono,
                            fontSize = 9.sp,
                            fontWeight =
                                FontWeight.Bold
                        )

                        Spacer(
                            Modifier.height(5.dp)
                        )

                        Text(
                            if (txSuccess)
                                txid
                            else
                                result!!,
                            color = TextMain,
                            fontFamily = Mono,
                            fontSize = 10.sp
                        )

                        if (txSuccess) {
                            Spacer(
                                Modifier.height(8.dp)
                            )

                            Text(
                                WalletLanguage.uiString("OPEN IN NOID EXPLORER  ↗"),
                                color = Cyan,
                                fontFamily = Mono,
                                fontSize = 9.sp,
                                fontWeight =
                                    FontWeight.Bold
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled =
                    !working &&
                    destination.isNotBlank() &&
                    amount.isNotBlank(),
                onClick = {
                    working = true
                    result = null

                    MainScope()
                        .launch {
                            val response =
                                withContext(
                                    Dispatchers.IO
                                ) {
                                    controller
                                        .sendNoid(
                                            destination,
                                            amount,
                                            fee
                                        )
                                }

                            result =
                                if (response.ok)
                                    "TX ${response.txid}"
                                else
                                    response.error
                                        ?: WalletLanguage.uiString("Send failed")

                            working = false
                        }
                }
            ) {
                Text(
                    if (working)
                        WalletLanguage.uiString("SENDING...")
                    else
                        WalletLanguage.uiString("SEND"),
                    color = Green,
                    fontFamily = Mono,
                    fontWeight =
                        FontWeight.Bold
                )
            }
        },
        dismissButton = {
            TextButton(
                enabled =
                    !working,
                onClick =
                    onDismiss
            ) {
                Text(
                    WalletLanguage.uiString("CLOSE"),
                    color = Muted,
                    fontFamily = Mono
                )
            }
        }
    )
}

@Composable
private fun ReceiveDialog(
    context: Context,
    address: String,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest =
            onDismiss,
        containerColor =
            Surface,
        title = {
            Column {
                AccentLabel(
                    text = WalletLanguage.uiString("RECEIVE"),
                    accent = Cyan
                )

                Spacer(
                    Modifier.height(10.dp)
                )

                Text(
                    WalletLanguage.uiString("RECEIVE NOID"),
                    color = TextMain,
                    fontFamily = Mono,
                    fontWeight =
                        FontWeight.Bold,
                    fontSize = 19.sp
                )
            }
        },
        text = {
            Column {
                Text(
                    WalletLanguage.uiString("ACTIVE ADDRESS"),
                    color = Muted,
                    fontFamily = Mono,
                    fontSize = 9.sp,
                    letterSpacing = 1.sp
                )

                Spacer(
                    Modifier.height(8.dp)
                )

                Column(
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .background(
                                Surface2,
                                RoundedCornerShape(
                                    10.dp
                                )
                            )
                            .border(
                                1.dp,
                                Cyan,
                                RoundedCornerShape(
                                    10.dp
                                )
                            )
                            .padding(14.dp)
                ) {
                    Text(
                        address,
                        color = TextMain,
                        fontFamily = Mono,
                        fontSize = 11.sp
                    )
                }

                Spacer(
                    Modifier.height(10.dp)
                )

                Text(
                    WalletLanguage.uiString("Share this address to receive NOID."),
                    color = Muted,
                    fontFamily = Mono,
                    fontSize = 10.sp
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    copyText(
                        context,
                        "Parano1d address",
                        address
                    )
                }
            ) {
                Text(
                    WalletLanguage.uiString("COPY ADDRESS"),
                    color = Cyan,
                    fontFamily = Mono,
                    fontWeight =
                        FontWeight.Bold
                )
            }
        },
        dismissButton = {
            TextButton(
                onClick =
                    onDismiss
            ) {
                Text(
                    WalletLanguage.uiString("CLOSE"),
                    color = Muted,
                    fontFamily = Mono
                )
            }
        }
    )
}

@Composable
private fun SettingsScreen(
    context: Context,
    controller: WalletController,
    node: NodeStatus,
    wallet: WalletInfo,
    onBack: () -> Unit,
    onDonate: () -> Unit,
    onDeleted: () -> Unit
) {
    var exportedKey by remember {
        mutableStateOf<String?>(null)
    }

    var exportError by remember {
        mutableStateOf<String?>(null)
    }

    var deleteDialog by remember {
        mutableStateOf(false)
    }

    var deleteText by remember {
        mutableStateOf("")
    }

    var deleteError by remember {
        mutableStateOf<String?>(null)
    }

    Column(
        modifier =
            Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .background(Bg)
                .verticalScroll(
                    rememberScrollState()
                )
                .padding(
                    horizontal = 18.dp,
                    vertical = 14.dp
                )
    ) {
        Row(
            modifier =
                Modifier.fillMaxWidth(),
            verticalAlignment =
                Alignment.CenterVertically
        ) {
            CompactOutlineButton(
                text = WalletLanguage.uiString("< BACK"),
                accent = Cyan,
                onClick =
                    onBack
            )

            Spacer(
                Modifier.weight(1f)
            )

            Logo(
                size = 20
            )
        }

        Spacer(
            Modifier.height(14.dp)
        )

        Text(
            WalletLanguage.uiString("SETTINGS"),
            color = TextMain,
            fontFamily = Mono,
            fontWeight =
                FontWeight.Bold,
            fontSize = 24.sp
        )

        Text(
            WalletLanguage.uiString("WALLET / NODE / SECURITY"),
            color = Muted,
            fontFamily = Mono,
            fontSize = 9.sp,
            letterSpacing = 1.sp
        )

        WalletLanguageSetting()

        Spacer(
            Modifier.height(18.dp)
        )

        TerminalCard(
            accent = Green
        ) {
            AccentLabel(
                text = WalletLanguage.uiString("WALLET"),
                accent = Green
            )

            Spacer(
                Modifier.height(12.dp)
            )

            Text(
                WalletLanguage.uiString("MASTER KEY BACKUP"),
                color = TextMain,
                fontFamily = Mono,
                fontWeight =
                    FontWeight.Bold,
                fontSize = 13.sp
            )

            Spacer(
                Modifier.height(6.dp)
            )

            Text(
                WalletLanguage.uiString("One master key derives every address in this wallet."),
                color = Muted,
                fontFamily = Mono,
                fontSize = 10.sp
            )

            Spacer(
                Modifier.height(14.dp)
            )

            ActionButton(
                text =
                    WalletLanguage.uiString("EXPORT MASTER KEY"),
                onClick = {
                    exportError = null

                    try {
                        exportedKey =
                            controller
                                .exportWallet()
                    } catch (
                        error: Throwable
                    ) {
                        exportError =
                            error.message
                                ?: error
                                    .javaClass
                                    .simpleName
                    }
                }
            )

            if (!exportError.isNullOrBlank()) {
                Spacer(
                    Modifier.height(12.dp)
                )

                ErrorText(
                    exportError!!
                )
            }
        }

        Spacer(
            Modifier.height(12.dp)
        )

        TerminalCard(
            accent = Magenta
        ) {
            AccentLabel(
                text = WalletLanguage.uiString("SUPPORT"),
                accent = Magenta
            )

            Spacer(
                Modifier.height(12.dp)
            )

            Text(
                WalletLanguage.uiString("SUPPORT PARANO1D"),
                color = TextMain,
                fontFamily = Mono,
                fontWeight =
                    FontWeight.Bold,
                fontSize = 13.sp
            )

            Spacer(
                Modifier.height(6.dp)
            )

            Text(
                WalletLanguage.uiString("Donate NOID directly from the active address."),
                color = Muted,
                fontFamily = Mono,
                fontSize = 10.sp
            )

            Spacer(
                Modifier.height(10.dp)
            )

            Text(
                "o1pgeng7j7f0aeuwpvrtf4qhkttddkr4xlyhjkjdz0d9rrt859md3sa9zhnn",
                color = Magenta,
                fontFamily = Mono,
                fontSize = 9.sp,
                maxLines = 2
            )

            Spacer(
                Modifier.height(14.dp)
            )

            AccentButton(
                text = WalletLanguage.uiString("DONATE"),
                accent = Magenta,
                onClick =
                    onDonate
            )
        }

        Spacer(
            Modifier.height(12.dp)
        )

        TerminalCard(
            accent = Cyan
        ) {
            AccentLabel(
                text = WalletLanguage.uiString("NODE"),
                accent = Cyan
            )

            Spacer(
                Modifier.height(12.dp)
            )

            InfoLine(
                WalletLanguage.uiString("STATUS"),
                if (node.running)
                    WalletLanguage.uiString("ONLINE")
                else
                    WalletLanguage.uiString("OFFLINE")
            )

            InfoLine(
                WalletLanguage.uiString("HEIGHT"),
                node.tipHeight
                    .toString()
            )

            InfoLine(
                WalletLanguage.uiString("SYNC"),
                if (node.running)
                    node.syncState
                else
                    WalletLanguage.uiString("OFFLINE")
            )

            InfoLine(
                WalletLanguage.uiString("PEERS"),
                node.peers
                    .toString()
            )
        }

        Spacer(
            Modifier.height(12.dp)
        )

        TerminalCard(
            accent = Danger
        ) {
            AccentLabel(
                text = WalletLanguage.uiString("DANGER"),
                accent = Danger
            )

            Spacer(
                Modifier.height(12.dp)
            )

            Text(
                WalletLanguage.uiString("DELETE WALLET"),
                color = TextMain,
                fontFamily = Mono,
                fontWeight =
                    FontWeight.Bold,
                fontSize = 13.sp
            )

            Spacer(
                Modifier.height(6.dp)
            )

            Text(
                WalletLanguage.uiString("Permanently removes the local master key and wallet metadata. The chain database is retained."),
                color = Muted,
                fontFamily = Mono,
                fontSize = 10.sp
            )

            Spacer(
                Modifier.height(14.dp)
            )

            DangerButton(
                text =
                    WalletLanguage.uiString("DELETE WALLET"),
                onClick = {
                    deleteDialog = true
                }
            )

            if (!deleteError.isNullOrBlank()) {
                Spacer(
                    Modifier.height(12.dp)
                )

                ErrorText(
                    deleteError!!
                )
            }
        }

        Spacer(
            Modifier.height(26.dp)
        )
    }

    if (exportedKey != null) {
        AlertDialog(
            onDismissRequest = {
                exportedKey = null
            },
            containerColor =
                Surface,
            title = {
                Column {
                    AccentLabel(
                        text = WalletLanguage.uiString("SECURITY"),
                        accent = Yellow
                    )

                    Spacer(
                        Modifier.height(10.dp)
                    )

                    Text(
                        WalletLanguage.uiString("MASTER KEY"),
                        color = TextMain,
                        fontFamily = Mono,
                        fontWeight =
                            FontWeight.Bold
                    )
                }
            },
            text = {
                Column {
                    Text(
                        WalletLanguage.uiString("Anyone with this key controls the wallet."),
                        color = Danger,
                        fontFamily = Mono,
                        fontSize = 10.sp
                    )

                    Spacer(
                        Modifier.height(12.dp)
                    )

                    Column(
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .background(
                                    Surface2,
                                    RoundedCornerShape(
                                        10.dp
                                    )
                                )
                                .border(
                                    1.dp,
                                    Yellow,
                                    RoundedCornerShape(
                                        10.dp
                                    )
                                )
                                .padding(12.dp)
                    ) {
                        Text(
                            exportedKey!!,
                            color = TextMain,
                            fontFamily = Mono,
                            fontSize = 11.sp
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        copyText(
                            context,
                            "Parano1d master key",
                            exportedKey!!
                        )
                    }
                ) {
                    Text(
                        WalletLanguage.uiString("COPY"),
                        color = Yellow,
                        fontFamily = Mono,
                        fontWeight =
                            FontWeight.Bold
                    )
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        exportedKey = null
                    }
                ) {
                    Text(
                        WalletLanguage.uiString("CLOSE"),
                        color = Muted,
                        fontFamily = Mono
                    )
                }
            }
        )
    }

    if (deleteDialog) {
        AlertDialog(
            onDismissRequest = {
                deleteDialog = false
                deleteText = ""
            },
            containerColor =
                Surface,
            title = {
                Column {
                    AccentLabel(
                        text = WalletLanguage.uiString("DANGER"),
                        accent = Danger
                    )

                    Spacer(
                        Modifier.height(10.dp)
                    )

                    Text(
                        WalletLanguage.uiString("DELETE WALLET"),
                        color = Danger,
                        fontFamily = Mono,
                        fontWeight =
                            FontWeight.Bold
                    )
                }
            },
            text = {
                Column {
                    Text(
                        WalletLanguage.uiString("This permanently removes the local master key."),
                        color = Danger,
                        fontFamily = Mono,
                        fontSize = 11.sp
                    )

                    Spacer(
                        Modifier.height(10.dp)
                    )

                    Text(
                        WalletLanguage.uiString("Type DELETE to confirm."),
                        color = Muted,
                        fontFamily = Mono,
                        fontSize = 10.sp
                    )

                    Spacer(
                        Modifier.height(10.dp)
                    )

                    OutlinedTextField(
                        value =
                            deleteText,
                        onValueChange = {
                            deleteText = it
                        },
                        modifier =
                            Modifier.fillMaxWidth(),
                        label = {
                            Text(
                                WalletLanguage.uiString("CONFIRM")
                            )
                        },
                        singleLine = true,
                        colors =
                            WalletInputColors()
                    )
                }
            },
            confirmButton = {
                TextButton(
                    enabled =
                        deleteText == "DELETE",
                    onClick = {
                        val result =
                            controller
                                .deleteWallet()

                        if (result.ok) {
                            deleteDialog = false
                            deleteText = ""
                            onDeleted()
                        } else {
                            deleteError =
                                result.error
                                    ?: WalletLanguage.uiString("Delete failed")
                        }
                    }
                ) {
                    Text(
                        WalletLanguage.uiString("DELETE"),
                        color = Danger,
                        fontFamily = Mono,
                        fontWeight =
                            FontWeight.Bold
                    )
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        deleteDialog = false
                        deleteText = ""
                    }
                ) {
                    Text(
                        WalletLanguage.uiString("CANCEL"),
                        color = Muted,
                        fontFamily = Mono
                    )
                }
            }
        )
    }
}

@Composable
private fun TerminalCard(
    accent: Color = Border,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        modifier =
            Modifier
                .fillMaxWidth()
                .background(
                    Surface,
                    RoundedCornerShape(
                        12.dp
                    )
                )
                .border(
                    1.dp,
                    accent.copy(
                        alpha = 0.72f
                    ),
                    RoundedCornerShape(
                        12.dp
                    )
                )
                .padding(14.dp),
        content =
            content
    )
}

@Composable
private fun AccentLabel(
    text: String,
    accent: Color
) {
    Box(
        modifier =
            Modifier
                .background(
                    accent,
                    RoundedCornerShape(
                        4.dp
                    )
                )
                .padding(
                    horizontal = 8.dp,
                    vertical = 4.dp
                )
    ) {
        Text(
            text,
            color = Bg,
            fontFamily = Mono,
            fontWeight =
                FontWeight.Bold,
            fontSize = 9.sp,
            letterSpacing = 1.sp
        )
    }
}

@Composable
private fun MetricCell(
    modifier: Modifier = Modifier,
    label: String,
    value: String,
    accent: Color
) {
    Column(
        modifier =
            modifier
                .background(
                    Surface2,
                    RoundedCornerShape(
                        8.dp
                    )
                )
                .padding(
                    horizontal = 10.dp,
                    vertical = 9.dp
                )
    ) {
        Text(
            label,
            color = Muted,
            fontFamily = Mono,
            fontSize = 8.sp
        )

        Spacer(
            Modifier.height(3.dp)
        )

        Text(
            value,
            color = accent,
            fontFamily = Mono,
            fontSize = 12.sp,
            fontWeight =
                FontWeight.Bold,
            maxLines = 1,
            overflow =
                TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun InfoLine(
    name: String,
    value: String
) {
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .padding(
                    vertical = 5.dp
                ),
        verticalAlignment =
            Alignment.CenterVertically
    ) {
        Text(
            name,
            color = Muted,
            fontFamily = Mono,
            fontSize = 9.sp
        )

        Spacer(
            Modifier.weight(1f)
        )

        Text(
            value,
            color = TextMain,
            fontFamily = Mono,
            fontSize = 10.sp,
            maxLines = 1,
            overflow =
                TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun ActionButton(
    text: String,
    enabled: Boolean = true,
    onClick: () -> Unit
) {
    Button(
        modifier =
            Modifier
                .fillMaxWidth()
                .height(52.dp),
        enabled =
            enabled,
        shape =
            RoundedCornerShape(
                8.dp
            ),
        colors =
            ButtonDefaults
                .buttonColors(
                    containerColor =
                        Green,
                    contentColor =
                        Bg,
                    disabledContainerColor =
                        Surface2,
                    disabledContentColor =
                        Muted
                ),
        onClick =
            onClick
    ) {
        Text(
            text,
            fontFamily = Mono,
            fontWeight =
                FontWeight.Bold,
            fontSize = 12.sp
        )
    }
}

@Composable
private fun AccentButton(
    text: String,
    accent: Color,
    enabled: Boolean = true,
    onClick: () -> Unit
) {
    Button(
        modifier =
            Modifier
                .fillMaxWidth()
                .height(52.dp),
        enabled =
            enabled,
        shape =
            RoundedCornerShape(
                8.dp
            ),
        colors =
            ButtonDefaults
                .buttonColors(
                    containerColor =
                        accent,
                    contentColor =
                        Bg,
                    disabledContainerColor =
                        Surface2,
                    disabledContentColor =
                        Muted
                ),
        onClick =
            onClick
    ) {
        Text(
            text,
            fontFamily = Mono,
            fontWeight =
                FontWeight.Bold,
            fontSize = 12.sp
        )
    }
}

@Composable
private fun DangerButton(
    text: String,
    onClick: () -> Unit
) {
    Button(
        modifier =
            Modifier.fillMaxWidth(),
        shape =
            RoundedCornerShape(
                8.dp
            ),
        colors =
            ButtonDefaults
                .buttonColors(
                    containerColor =
                        Danger,
                    contentColor =
                        Bg
                ),
        onClick =
            onClick
    ) {
        Text(
            text,
            fontFamily = Mono,
            fontWeight =
                FontWeight.Bold,
            fontSize = 12.sp
        )
    }
}


@Composable
private fun OutlineActionButton(
    text: String,
    accent: Color,
    enabled: Boolean = true,
    onClick: () -> Unit
) {
    Button(
        modifier =
            Modifier
                .fillMaxWidth()
                .height(48.dp)
                .border(
                    1.dp,
                    accent,
                    RoundedCornerShape(
                        8.dp
                    )
                ),
        enabled =
            enabled,
        shape =
            RoundedCornerShape(
                8.dp
            ),
        colors =
            ButtonDefaults
                .buttonColors(
                    containerColor =
                        Surface2,
                    contentColor =
                        accent,
                    disabledContainerColor =
                        Surface2,
                    disabledContentColor =
                        Muted
                ),
        onClick =
            onClick
    ) {
        Text(
            text,
            color =
                if (enabled)
                    accent
                else
                    Muted,
            fontFamily = Mono,
            fontWeight =
                FontWeight.Bold,
            fontSize = 11.sp,
            letterSpacing = 1.sp
        )
    }
}

@Composable
private fun CompactOutlineButton(
    text: String,
    accent: Color,
    onClick: () -> Unit
) {
    Button(
        modifier =
            Modifier
                .height(38.dp)
                .border(
                    1.dp,
                    accent,
                    RoundedCornerShape(
                        7.dp
                    )
                ),
        shape =
            RoundedCornerShape(
                7.dp
            ),
        colors =
            ButtonDefaults
                .buttonColors(
                    containerColor =
                        Surface,
                    contentColor =
                        accent
                ),
        onClick =
            onClick
    ) {
        Text(
            text,
            color = accent,
            fontFamily = Mono,
            fontWeight =
                FontWeight.Bold,
            fontSize = 9.sp
        )
    }
}

@Composable
private fun ErrorText(
    text: String
) {
    Text(
        text = text,
        color = Danger,
        fontFamily = Mono,
        fontSize = 11.sp
    )
}

private fun copyText(
    context: Context,
    label: String,
    value: String
) {
    val clipboard =
        context.getSystemService(
            Context.CLIPBOARD_SERVICE
        ) as ClipboardManager

    clipboard.setPrimaryClip(
        ClipData.newPlainText(
            label,
            value
        )
    )
}
