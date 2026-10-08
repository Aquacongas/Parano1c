package org.parano1d.mobile

import android.content.Context
import org.json.JSONObject
import java.math.BigDecimal
import java.math.RoundingMode

data class RecentTransaction(
    val txid: String,
    val direction: String,
    val amountMicronoid: Long,
    val height: Long,
    val timestamp: Long,
    val pending: Boolean,
    val coinbase: Boolean
)

class WalletController(
    context: Context
) {

    private val dataDir =
        context.filesDir.absolutePath

    fun walletConfigured(): Boolean {
        val json =
            JSONObject(
                NativeNode.walletConfigured(
                    dataDir
                )
            )

        if (!json.optBoolean("ok", false)) {
            error(
                json.optString(
                    "error",
                    "walletConfigured failed"
                )
            )
        }

        return json.optBoolean(
            "configured",
            false
        )
    }

    fun createWallet(): NativeResult =
        parseBasic(
            NativeNode.createWallet(
                dataDir
            )
        )

    fun importWallet(
        masterKey: String
    ): NativeResult =
        parseBasic(
            NativeNode.importWallet(
                dataDir,
                masterKey
            )
        )

    fun exportWallet(): String {
        val json =
            JSONObject(
                NativeNode.exportWallet(
                    dataDir
                )
            )

        if (!json.optBoolean("ok", false)) {
            error(
                json.optString(
                    "error",
                    "wallet export failed"
                )
            )
        }

        return json.getString(
            "master_key"
        )
    }

    fun deleteWallet(): NativeResult =
        parseBasic(
            NativeNode.deleteWallet(
                dataDir
            )
        )

    fun start(): NativeResult =
        parseBasic(
            NativeNode.startNode(
                dataDir
            )
        )

    fun stop(): NativeResult =
        parseBasic(
            NativeNode.stopNode()
        )

    fun status(): NodeStatus {
        return try {
            val json =
                JSONObject(
                    NativeNode.status()
                )

            NodeStatus(
                running =
                    json.optBoolean(
                        "running",
                        false
                    ),

                tipHeight =
                    json.optLong(
                        "tip_height",
                        0
                    ),

                tipHash =
                    json.optString(
                        "tip_hash",
                        ""
                    ),

                peers =
                    json.optInt(
                        "peers",
                        0
                    ),

                syncing =
                    json.optBoolean(
                        "syncing",
                        false
                    ),

                syncState =
                    json.optString(
                        "sync_state",
                        "WAITING"
                    ),

                historyStepReady =
                    json.optBoolean(
                        "history_step_ready",
                        false
                    ),

                error =
                    nullableString(
                        json,
                        "error"
                    )
            )
        } catch (
            error: Throwable
        ) {
            NodeStatus(
                error =
                    error.message
                        ?: error.javaClass.simpleName
            )
        }
    }

    fun wallet(): WalletInfo {
        return try {
            val json =
                JSONObject(
                    NativeNode.walletInfo()
                )

            WalletInfo(
                address =
                    nullableString(
                        json,
                        "address"
                    ) ?: "",

                balanceMicronoid =
                    json.optLong(
                        "balance_micronoid",
                        0
                    ),

                error =
                    nullableString(
                        json,
                        "error"
                    )
            )
        } catch (
            error: Throwable
        ) {
            WalletInfo(
                error =
                    error.message
                        ?: error.javaClass.simpleName
            )
        }
    }

    fun sendNoid(
        destination: String,
        amountNoid: String,
        feeNoid: String
    ): SendResponse {
        return try {

            val amount =
                noidToMicronoid(
                    amountNoid
                )

            val feeText =
                feeNoid
                    .trim()
                    .replace(',', '.')

            val fee =
                if (
                    feeText.isBlank() ||
                    BigDecimal(feeText)
                        .compareTo(
                            BigDecimal.ZERO
                        ) == 0
                ) {
                    0L
                } else {
                    noidToMicronoid(
                        feeText
                    )
                }

            val json =
                JSONObject(
                    NativeNode.send(
                        destination.trim(),
                        amount,
                        fee
                    )
                )

            SendResponse(
                ok =
                    json.optBoolean(
                        "ok",
                        false
                    ),

                txid =
                    nullableString(
                        json,
                        "txid"
                    ),

                error =
                    nullableString(
                        json,
                        "error"
                    )
            )

        } catch (
            error: Throwable
        ) {
            SendResponse(
                ok = false,
                error =
                    error.message
                        ?: error.javaClass.simpleName
            )
        }
    }


    fun sendAll(
        destination: String
    ): SendResponse {
        return try {
            val json =
                JSONObject(
                    NativeNode.sendAll(
                        destination.trim()
                    )
                )

            SendResponse(
                ok =
                    json.optBoolean(
                        "ok",
                        false
                    ),
                txid =
                    nullableString(
                        json,
                        "txid"
                    ),
                error =
                    nullableString(
                        json,
                        "error"
                    )
            )
        } catch (
            error: Throwable
        ) {
            SendResponse(
                ok = false,
                error =
                    error.message
                        ?: error.javaClass.simpleName
            )
        }
    }

    fun recentTransactions(
        limit: Int = 5
    ): List<RecentTransaction> {
        return try {
            val json =
                JSONObject(
                    NativeNode
                        .recentTransactions(
                            limit
                        )
                )

            if (!json.optBoolean("ok", false)) {
                emptyList()
            } else {
                val array =
                    json.optJSONArray(
                        "transactions"
                    )

                buildList {
                    if (array != null) {
                        for (
                            index in
                            0 until array.length()
                        ) {
                            val item =
                                array.getJSONObject(
                                    index
                                )

                            add(
                                RecentTransaction(
                                    txid =
                                        item.optString(
                                            "txid",
                                            ""
                                        ),
                                    direction =
                                        item.optString(
                                            "direction",
                                            ""
                                        ),
                                    amountMicronoid =
                                        item.optLong(
                                            "amount_micronoid",
                                            0
                                        ),
                                    height =
                                        item.optLong(
                                            "height",
                                            0
                                        ),
                                    timestamp =
                                        item.optLong(
                                            "timestamp",
                                            0
                                        ),
                                    pending =
                                        item.optBoolean(
                                            "pending",
                                            false
                                        ),
                                    coinbase =
                                        item.optBoolean(
                                            "is_coinbase",
                                            false
                                        )
                                )
                            )
                        }
                    }
                }
            }
        } catch (
            _: Throwable
        ) {
            emptyList()
        }
    }


    fun walletOverview(): WalletOverview =
        parseWalletOverview(
            NativeNode.walletOverview()
        )

    fun newAddress(): WalletOverview =
        parseWalletOverview(
            NativeNode.newAddress()
        )

    fun setActiveAddress(
        keyIndex: Int
    ): WalletOverview =
        parseWalletOverview(
            NativeNode.setActiveAddress(
                keyIndex
            )
        )

    private fun parseWalletOverview(
        raw: String
    ): WalletOverview {
        val json =
            JSONObject(raw)

        if (!json.optBoolean("ok", false)) {
            return WalletOverview(
                error =
                    nullableString(
                        json,
                        "error"
                    )
                        ?: "Wallet operation failed"
            )
        }

        val array =
            json.optJSONArray(
                "addresses"
            )

        val addresses =
            buildList {
                if (array != null) {
                    for (
                        index in
                        0 until array.length()
                    ) {
                        val item =
                            array.getJSONObject(
                                index
                            )

                        add(
                            WalletAddress(
                                keyIndex =
                                    item.getInt(
                                        "key_index"
                                    ),

                                address =
                                    item.getString(
                                        "address"
                                    ),

                                balanceMicronoid =
                                    item.getLong(
                                        "balance_micronoid"
                                    ),

                                active =
                                    item.getBoolean(
                                        "is_active"
                                    )
                            )
                        )
                    }
                }
            }

        return WalletOverview(
            availableBalanceMicronoid =
                json.optLong(
                    "available_balance_micronoid",
                    0
                ),

            activeBalanceMicronoid =
                json.optLong(
                    "active_balance_micronoid",
                    0
                ),

            activeIndex =
                json.optInt(
                    "active_index",
                    0
                ),

            addressCount =
                json.optInt(
                    "address_count",
                    addresses.size
                ),

            addresses =
                addresses
        )
    }


    companion object {

        private val MICRO =
            BigDecimal("1000000")

        fun noidToMicronoid(
            text: String
        ): Long {

            val amount =
                text
                    .trim()
                    .replace(',', '.')
                    .toBigDecimal()

            require(
                amount > BigDecimal.ZERO
            ) {
                "Amount must be greater than zero"
            }

            val micronoid =
                amount
                    .multiply(MICRO)
                    .setScale(
                        0,
                        RoundingMode.UNNECESSARY
                    )

            return micronoid.longValueExact()
        }

        fun formatNoid(
            micronoid: Long
        ): String =
            BigDecimal
                .valueOf(micronoid)
                .divide(MICRO)
                .stripTrailingZeros()
                .toPlainString()

        private fun nullableString(
            json: JSONObject,
            key: String
        ): String? =
            if (
                !json.has(key) ||
                json.isNull(key)
            ) {
                null
            } else {
                json.optString(key)
                    .takeUnless {
                        it == "null"
                    }
            }

        private fun parseBasic(
            raw: String
        ): NativeResult {
            val json =
                JSONObject(raw)

            return NativeResult(
                ok =
                    json.optBoolean(
                        "ok",
                        false
                    ),

                error =
                    nullableString(
                        json,
                        "error"
                    )
            )
        }
    }
}
