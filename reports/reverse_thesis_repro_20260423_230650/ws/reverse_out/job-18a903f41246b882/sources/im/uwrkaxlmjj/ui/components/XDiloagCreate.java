package im.uwrkaxlmjj.ui.components;

import android.app.Dialog;
import android.content.Context;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class XDiloagCreate {
    public static XDialog.Builder createSimpleAlert(Context context, String title, String text) {
        if (text == null) {
            return null;
        }
        XDialog.Builder builder = new XDialog.Builder(context);
        builder.setTitle(title == null ? LocaleController.getString("AppName", R.string.AppName) : title);
        builder.setMessage(text);
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        return builder;
    }

    public static Dialog showSimpleAlert(BaseFragment baseFragment, String title, String text) {
        if (text == null || baseFragment == null || baseFragment.getParentActivity() == null) {
            return null;
        }
        XDialog.Builder builder = createSimpleAlert(baseFragment.getParentActivity(), title, text);
        Dialog dialog = builder.create();
        baseFragment.showDialog(dialog);
        return dialog;
    }
}
