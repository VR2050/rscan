package im.uwrkaxlmjj.ui.dialogs;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.view.Display;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class DialogNearPersonFilter extends Dialog {
    public DialogNearPersonFilter(Activity context) {
        super(context, R.plurals.commondialog);
        View view = LayoutInflater.from(getContext()).inflate(R.layout.dialog_near_person_filter, (ViewGroup) null);
        setContentView(view);
        WindowManager m = context.getWindowManager();
        Display d = m.getDefaultDisplay();
        Window window = getWindow();
        WindowManager.LayoutParams lp = window.getAttributes();
        window.setGravity(80);
        lp.width = d.getWidth();
        window.setAttributes(lp);
        setCancelable(true);
    }

    public DialogNearPersonFilter(Context context, int themeResId) {
        super(context, themeResId);
    }

    protected DialogNearPersonFilter(Context context, boolean cancelable, DialogInterface.OnCancelListener cancelListener) {
        super(context, cancelable, cancelListener);
    }
}
