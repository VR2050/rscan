package im.uwrkaxlmjj.ui.hui.contacts;

import android.text.TextUtils;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.tgnet.TLRPC;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ContactsUtils {
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    public static String getAboutContactsErrText(TLRPC.TL_error error) {
        if (error == null || TextUtils.isEmpty(error.text)) {
            String result = LocaleController.getString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater);
            return result;
        }
        String str = error.text;
        byte b = -1;
        switch (str.hashCode()) {
            case -435956621:
                if (str.equals("USER_HAS_BEEN_BLOCK")) {
                    b = 1;
                }
                break;
            case 100175290:
                if (str.equals("TOO_MANY_REQUEST")) {
                    b = 3;
                }
                break;
            case 721996124:
                if (str.equals("CONTACT_HAS_ADDED")) {
                    b = 2;
                }
                break;
            case 1986852397:
                if (str.equals("CAN_NOT_BE_SELF")) {
                    b = 0;
                }
                break;
        }
        if (b == 0) {
            String result2 = LocaleController.getString("CantAddYourSelf", R.string.CantAddYourSelf);
            return result2;
        }
        if (b == 1) {
            String result3 = LocaleController.getString("HasBeenBlocked", R.string.HasBeenBlocked);
            return result3;
        }
        if (b == 2) {
            String result4 = LocaleController.getString("AlreadyYourContact", R.string.AlreadyYourContact);
            return result4;
        }
        if (b == 3) {
            String result5 = LocaleController.getString("OperationTooMany", R.string.OperationTooMany);
            return result5;
        }
        String result6 = LocaleController.getString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater);
        return result6;
    }
}
