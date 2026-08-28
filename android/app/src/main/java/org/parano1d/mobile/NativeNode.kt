package org.parano1d.mobile

object NativeNode {
    init {
        System.loadLibrary("noid_mobile_ffi")
    }

    external fun walletConfigured(dataDir: String): String

    external fun createWallet(dataDir: String): String

    external fun importWallet(
        dataDir: String,
        masterKey: String
    ): String

    external fun exportWallet(dataDir: String): String

    external fun deleteWallet(dataDir: String): String

    external fun startNode(dataDir: String): String

    external fun stopNode(): String

    external fun status(): String

    external fun walletInfo(): String

    external fun walletOverview(): String

    external fun newAddress(): String

    external fun setActiveAddress(
        keyIndex: Int
    ): String

    external fun send(
        destination: String,
        amountMicronoid: Long,
        feeMicronoid: Long
    ): String


    external fun sendAll(
        destination: String
    ): String

    external fun recentTransactions(
        limit: Int
    ): String
}
