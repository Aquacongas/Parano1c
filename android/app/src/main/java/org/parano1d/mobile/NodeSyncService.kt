package org.parano1d.mobile

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** One service owns the native node; Compose only observes its state. */
class NodeSyncService : Service() {
    companion object {
        private const val RUN_CHANNEL = "parano_node"
        private const val INCOMING_CHANNEL = "parano_incoming"
        private const val RUN_ID = 1001
        private const val PREFS = "parano_incoming_notifications_v1"

        fun start(context: android.content.Context) {
            val intent = Intent(context, NodeSyncService::class.java)
            androidx.core.content.ContextCompat.startForegroundService(context, intent)
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var worker: Job? = null
    private lateinit var controller: WalletController

    override fun onCreate() {
        super.onCreate()
        controller = WalletController(applicationContext)
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(RUN_CHANNEL, "Parano1c node", NotificationManager.IMPORTANCE_LOW))
        manager.createNotificationChannel(NotificationChannel(INCOMING_CHANNEL, "Parano1c incoming transactions", NotificationManager.IMPORTANCE_DEFAULT))
        // Android requires promotion to foreground promptly, before Rust initialization.
        val note = statusNotification(WalletLanguage.string(this, R.string.p1_node_starting))
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(RUN_ID, note, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(RUN_ID, note)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (worker?.isActive != true) {
            worker = scope.launch {
                try {
                    val result = controller.start()
                    if (!result.ok && controller.status().running != true) {
                        Log.e("NOID_SERVICE", "Node start failed: ${result.error}")
                        stopSelf()
                        return@launch
                    }
                    while (isActive) {
                        val status = controller.status()
                        getSystemService(NotificationManager::class.java).notify(
                            RUN_ID,
                            statusNotification(WalletLanguage.format(this@NodeSyncService, R.string.p1_node_status, status.tipHeight, status.peers))
                        )
                        if (status.running) checkIncoming()
                        delay(15_000L)
                    }
                } catch (error: Exception) {
                    Log.e("NOID_SERVICE", "Node service error", error)
                    stopSelf()
                }
            }
        }
        // After process death user opens wallet to restart; never auto-start without UI.
        return START_NOT_STICKY
    }

    private fun statusNotification(message: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, RUN_CHANNEL)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(WalletLanguage.string(this, R.string.p1_node_active))
            .setContentText(message)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }

    private fun checkIncoming() {
        val wallet = controller.wallet()
        if (wallet.address.isBlank() || wallet.error != null) return
        val status = controller.status()
        if (status.tipHeight <= 0) return
        val transactions = controller.recentTransactions(100)
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        // Use wallet identity to avoid stale notifications across account changes.
        val identity = wallet.address
        val key = "seen_" + identity
        val previous = prefs.getStringSet(key, null)
        val incoming = transactions.filter {
            it.direction.equals("RECEIVED", ignoreCase = true) &&
                !it.pending && it.txid.isNotBlank() && it.amountMicronoid > 0
        }
        val current = incoming.map { it.txid }.toSet()
        if (previous == null) {
            // First scan is a baseline: never notify about entire historical wallet.
            prefs.edit().putStringSet(key, current).apply()
            return
        }
        val newlySeen = incoming.filter { !previous.contains(it.txid) }
        for (tx in newlySeen) {
            val open = PendingIntent.getActivity(
                this, tx.txid.hashCode(), Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val notification = NotificationCompat.Builder(this, INCOMING_CHANNEL)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(WalletLanguage.string(this, R.string.p1_incoming_payment))
                .setContentText(WalletLanguage.format(this, R.string.p1_payment_confirmed, "+${WalletController.formatNoid(tx.amountMicronoid)}"))
                .setContentIntent(open)
                .setAutoCancel(true)
                .build()
            try {
                NotificationManagerCompat.from(this).notify(tx.txid.hashCode(), notification)
            } catch (error: SecurityException) {
                Log.w("NOID_SERVICE", "Notifications disabled", error)
            }
        }
        // Preserve older IDs while bounding storage. A recent list cannot re-alert on restart.
        val stored = (previous + current).toList().takeLast(2000).toSet()
        prefs.edit().putStringSet(key, stored).apply()
    }

    override fun onTimeout(startId: Int, fgsType: Int) {
        Log.i("NOID_SERVICE", "Android dataSync FGS time limit reached")
        stopSelf()
    }

    // A swipe from Android Recents removes the wallet task.  Stop the node,
    // rather than leaving the foreground service synchronizing indefinitely.
    override fun onTaskRemoved(rootIntent: Intent?) {
        Log.i("NOID_SERVICE", "WALLET TASK REMOVED — stopping node and P2P")
        stopSelf()
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        worker?.cancel()
        scope.cancel()
        // Stop only when foreground service lifetime ends, never on Activity pause.
        try { controller.stop() } catch (error: Exception) {
            Log.w("NOID_SERVICE", "Stop failed", error)
        }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
