package im.uwrkaxlmjj.ui.wallet.utils;

import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletErrorUtil;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ExceptionUtils {
    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0050  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean handleCommonError(java.lang.String r3) {
        /*
            Method dump skipped, instruction units count: 212
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.wallet.utils.ExceptionUtils.handleCommonError(java.lang.String):boolean");
    }

    public static void handleCreateAccountError(String error) {
        if (handleCommonError(error)) {
            return;
        }
        byte b = -1;
        if (error.hashCode() == 1260306429 && error.equals("ERROR_ACCOUNT_SYNCHRONIZED")) {
            b = 0;
        }
        if (b == 0) {
            ToastUtils.show((CharSequence) LocaleController.getString(R.string.WalletAccountCreated));
        }
    }

    public static void handleGetAccountInfoError(String error) {
        if (handleCommonError(error)) {
            return;
        }
        byte b = -1;
        if (error.hashCode() == 1260306429 && error.equals("ERROR_ACCOUNT_SYNCHRONIZED")) {
            b = 0;
        }
        if (b == 0) {
            ToastUtils.show((CharSequence) LocaleController.getString(R.string.WalletAccountCreated));
        }
    }

    public static void handlePaymentPasswordException(String ex) {
        if (handleCommonError(ex)) {
        }
        switch (ex) {
            case "ERROR_PAY_PASSWORD_NOT_NULL":
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.PayPasswordNotNull));
                break;
            case "ERROR_CONFIRM_PAY_PASSWORD_NOT_NULL":
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.ComfirmPayPasswordNotNull));
                break;
            case "ERROR_NEW_PASSWORD_IS_INCONSISTENT":
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.NewPasswordInconsistent));
                break;
            case "TYPE_IS_NOT_NULL":
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.TypeCannotBeEmpty));
                break;
            case "SAFETY_CODE_NULL":
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.SecurityCodeNotNull));
                break;
            case "SMS_CODE_NULL":
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.VertificationCodeNotNull));
                break;
            case "ERROR_OLD_PASSWORD_NOT_NULL":
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.OldPasswordNotNull));
                break;
            default:
                ToastUtils.show((CharSequence) WalletErrorUtil.getErrorDescription(ex));
                break;
        }
    }

    public static void handlePayChannelException(String ex) {
        if (handleCommonError(ex)) {
            return;
        }
        ToastUtils.show((CharSequence) WalletErrorUtil.getErrorDescription(ex));
    }

    public static void handleWithdrawException(String ex) {
        if (handleCommonError(ex)) {
            return;
        }
        ToastUtils.show((CharSequence) WalletErrorUtil.getErrorDescription(ex));
    }
}
