package org.lagrange.dev.packet.login

open class QrCodeState(val value: Byte) {
    data object Confirmed : QrCodeState(0)
    data object CodeExpired : QrCodeState(17)
    data object WaitingForScan : QrCodeState(48)
    data object WaitingForConfirm : QrCodeState(53)
    data object Canceled : QrCodeState(54)
    
    companion object {
        fun values(): Array<QrCodeState> {
            return arrayOf(Confirmed, CodeExpired, WaitingForScan, WaitingForConfirm, Canceled)
        }

        fun valueOf(value: String): QrCodeState {
            return when (value) {
                "Confirmed" -> Confirmed
                "CodeExpired" -> CodeExpired
                "WaitingForScan" -> WaitingForScan
                "WaitingForConfirm" -> WaitingForConfirm
                "Canceled" -> Canceled
                else -> throw IllegalArgumentException("No object org.lagrange.dev.packet.login.QrCodeState.$value")
            }
        }
    }
}