package org.parano1d.mobile

data class NodeStatus(
    val running: Boolean = false,
    val tipHeight: Long = 0,
    val tipHash: String = "",
    val peers: Int = 0,
    val syncing: Boolean = false,
    val syncState: String = "OFFLINE",
    val historyStepReady: Boolean = false,
    val error: String? = null
)

data class WalletInfo(
    val address: String = "",
    val balanceMicronoid: Long = 0,
    val error: String? = null
)

data class NativeResult(
    val ok: Boolean,
    val error: String? = null
)

data class SendResponse(
    val ok: Boolean,
    val txid: String? = null,
    val error: String? = null
)

data class WalletAddress(
    val keyIndex: Int,
    val address: String,
    val balanceMicronoid: Long,
    val active: Boolean
)

data class WalletOverview(
    val availableBalanceMicronoid: Long = 0,
    val activeBalanceMicronoid: Long = 0,
    val activeIndex: Int = 0,
    val addressCount: Int = 0,
    val addresses: List<WalletAddress> = emptyList(),
    val error: String? = null
) {
    val activeAddress: WalletAddress?
        get() = addresses.firstOrNull { it.active }
}
