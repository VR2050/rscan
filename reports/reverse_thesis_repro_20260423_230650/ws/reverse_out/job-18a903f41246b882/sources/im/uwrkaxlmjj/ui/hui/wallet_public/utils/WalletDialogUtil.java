package im.uwrkaxlmjj.ui.hui.wallet_public.utils;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.dialogs.WalletDialog;
import im.uwrkaxlmjj.ui.fragments.BaseFmts;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WalletDialogUtil {
    public static WalletDialog showConfirmBtnWalletDialog(Object host, CharSequence msg) {
        return showConfirmBtnWalletDialog(host, msg, true);
    }

    public static WalletDialog showConfirmBtnWalletDialog(Object host, CharSequence msg, boolean cancelable) {
        return showConfirmBtnWalletDialog(host, msg, cancelable, null, null);
    }

    public static WalletDialog showConfirmBtnWalletDialog(Object host, CharSequence msg, boolean cancelable, DialogInterface.OnClickListener onConfirmClickListener) {
        return showConfirmBtnWalletDialog(host, msg, cancelable, onConfirmClickListener, null);
    }

    public static WalletDialog showConfirmBtnWalletDialog(Object host, CharSequence msg, boolean cancelable, DialogInterface.OnDismissListener onDismissListener) {
        return showConfirmBtnWalletDialog(host, msg, cancelable, null, onDismissListener);
    }

    public static WalletDialog showConfirmBtnWalletDialog(Object host, CharSequence msg, boolean cancelable, DialogInterface.OnClickListener onConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        return showSingleBtnWalletDialog(host, "", msg, LocaleController.getString("Confirm", R.string.Confirm), cancelable, onConfirmClickListener, onDismissListener);
    }

    public static WalletDialog showConfirmBtnWalletDialog(Object host, String title, CharSequence msg, boolean cancelable, DialogInterface.OnClickListener onConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        return showSingleBtnWalletDialog(host, title, msg, LocaleController.getString("Confirm", R.string.Confirm), cancelable, onConfirmClickListener, onDismissListener);
    }

    public static WalletDialog showSingleBtnWalletDialog(Object host, CharSequence msg, DialogInterface.OnClickListener onConfirmClickListener) {
        return showSingleBtnWalletDialog(host, msg, LocaleController.getString(R.string.OK), true, onConfirmClickListener, null);
    }

    public static WalletDialog showSingleBtnWalletDialog(Object host, CharSequence msg, boolean cancelable, DialogInterface.OnClickListener onConfirmClickListener) {
        return showSingleBtnWalletDialog(host, msg, LocaleController.getString(R.string.OK), cancelable, onConfirmClickListener, null);
    }

    public static WalletDialog showSingleBtnWalletDialog(Object host, CharSequence msg, String buttonText, boolean cancelable, DialogInterface.OnClickListener onConfirmClickListener) {
        return showSingleBtnWalletDialog(host, msg, buttonText, cancelable, onConfirmClickListener, null);
    }

    public static WalletDialog showSingleBtnWalletDialog(Object host, CharSequence msg, String buttonText, boolean cancelable, DialogInterface.OnDismissListener onDismissListener) {
        return showSingleBtnWalletDialog(host, msg, buttonText, cancelable, null, onDismissListener);
    }

    public static WalletDialog showSingleBtnWalletDialog(Object host, CharSequence msg, String buttonText, boolean cancelable, DialogInterface.OnClickListener onConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        return showWalletDialog(host, "", msg, null, buttonText, cancelable, null, onConfirmClickListener, onDismissListener);
    }

    public static WalletDialog showSingleBtnWalletDialog(Object host, String title, CharSequence msg, String buttonText, boolean cancelable, DialogInterface.OnClickListener onConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        return showWalletDialog(host, title, msg, null, buttonText, cancelable, null, onConfirmClickListener, onDismissListener);
    }

    public static WalletDialog showRedpkgTransDialog(Object host, String title, String conent) {
        return null;
    }

    public static WalletDialog showWalletDialog(Object host, CharSequence msg, String confirmButtonText, DialogInterface.OnClickListener onConfirmClickListener) {
        return showWalletDialog(host, null, msg, null, confirmButtonText, true, null, onConfirmClickListener, null);
    }

    public static WalletDialog showWalletDialog(Object host, CharSequence msg, String confirmButtonText, boolean cancelable, DialogInterface.OnClickListener onConfirmClickListener) {
        return showWalletDialog(host, null, msg, null, confirmButtonText, cancelable, null, onConfirmClickListener, null);
    }

    public static WalletDialog showWalletDialog(Object host, String title, CharSequence msg, String confirmButtonText, DialogInterface.OnClickListener onConfirmClickListener) {
        return showWalletDialog(host, title, msg, null, confirmButtonText, true, null, onConfirmClickListener, null);
    }

    public static WalletDialog showWalletDialog(Object host, String title, CharSequence msg, String confirmButtonText, boolean cancelable, DialogInterface.OnClickListener onConfirmClickListener) {
        return showWalletDialog(host, title, msg, null, confirmButtonText, cancelable, null, onConfirmClickListener, null);
    }

    public static WalletDialog showWalletDialog(Object host, CharSequence msg, String confirmButtonText, DialogInterface.OnClickListener onConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        return showWalletDialog(host, null, msg, null, confirmButtonText, true, null, onConfirmClickListener, onDismissListener);
    }

    public static WalletDialog showWalletDialog(Object host, CharSequence msg, String confirmButtonText, boolean cancelable, DialogInterface.OnClickListener onConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        return showWalletDialog(host, null, msg, null, confirmButtonText, cancelable, null, onConfirmClickListener, onDismissListener);
    }

    public static WalletDialog showWalletDialog(Object host, CharSequence msg, String confirmButtonText, DialogInterface.OnClickListener onCancelClickListener, DialogInterface.OnClickListener onConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        return showWalletDialog(host, null, msg, null, confirmButtonText, true, onCancelClickListener, onConfirmClickListener, onDismissListener);
    }

    public static WalletDialog showWalletDialog(Object host, CharSequence msg, String confirmButtonText, boolean cancelable, DialogInterface.OnClickListener onCancelClickListener, DialogInterface.OnClickListener onConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        return showWalletDialog(host, null, msg, null, confirmButtonText, cancelable, onCancelClickListener, onConfirmClickListener, onDismissListener);
    }

    public static WalletDialog showWalletDialog(Object host, String title, CharSequence msg, String cancelButtonText, String confirmButtonText, DialogInterface.OnClickListener onCancelClickListener, DialogInterface.OnClickListener onConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        WalletDialog walletDialog = showWalletDialog(host, title, msg, cancelButtonText, confirmButtonText, true, onCancelClickListener, onConfirmClickListener, onDismissListener);
        if (walletDialog != null) {
            if (walletDialog.getNegativeButton() != null) {
                walletDialog.getNegativeButton().setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
            }
            if (walletDialog.getPositiveButton() != null) {
                walletDialog.getPositiveButton().setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
            }
        }
        return walletDialog;
    }

    public static WalletDialog showWalletDialog(Object host, String title, CharSequence msg, String cancelButtonText, String confirmButtonText, boolean cancelable, DialogInterface.OnClickListener onCancelClickListener, DialogInterface.OnClickListener onConfirmClickListener, DialogInterface.OnDismissListener onDismissListener) {
        if (!(host instanceof BaseFragment) && !(host instanceof BaseFmts) && !(host instanceof Activity)) {
            return null;
        }
        Context context = null;
        if (host instanceof BaseFragment) {
            context = ((BaseFragment) host).getParentActivity();
        } else if (host instanceof BaseFmts) {
            context = ((BaseFmts) host).getParentActivity();
        }
        if (context == null) {
            return null;
        }
        WalletDialog dialog = new WalletDialog(context);
        dialog.setCancelable(false);
        if (title == null) {
            title = LocaleController.getString("AppName", R.string.AppName);
        }
        dialog.setTitle(title);
        dialog.setMessage(msg);
        if (cancelButtonText != null) {
            dialog.setNegativeButton(cancelButtonText, onCancelClickListener);
        }
        if (confirmButtonText == null) {
            confirmButtonText = LocaleController.getString("OK", R.string.OK);
        }
        dialog.setPositiveButton(confirmButtonText, onConfirmClickListener);
        if (host instanceof BaseFragment) {
            ((BaseFragment) host).showDialog(dialog, onDismissListener);
        } else if (host instanceof BaseFmts) {
            ((BaseFmts) host).showDialog(dialog, onDismissListener);
        }
        if (!cancelable) {
            dialog.setCancelable(false);
        }
        return dialog;
    }
}
