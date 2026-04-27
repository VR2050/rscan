package im.uwrkaxlmjj.ui.hui.packet.dialogs;

import android.app.Dialog;
import android.content.Context;
import android.graphics.drawable.ColorDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.TextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class LoadingDialog extends Dialog {
    private LoadingDialogDelegate delegate;
    private FrameLayout ffLoadingContainer;
    private Context mContext;
    private TextView tvLoadingView;

    public interface LoadingDialogDelegate {
        void onClick();
    }

    public void setDelegate(LoadingDialogDelegate delegate) {
        this.delegate = delegate;
    }

    public LoadingDialog(Context context) {
        super(context);
        this.mContext = context;
        initLyouat(context);
        setCanceledOnTouchOutside(false);
        setCancelable(false);
    }

    private void initLyouat(Context context) {
        View view = LayoutInflater.from(context).inflate(R.layout.dialog_loading_layout, (ViewGroup) null);
        setContentView(view);
        Window window = getWindow();
        if (window != null) {
            window.setBackgroundDrawable(new ColorDrawable());
            WindowManager.LayoutParams params = window.getAttributes();
            params.gravity = 17;
            window.setAttributes(params);
            this.tvLoadingView = (TextView) window.findViewById(R.attr.tv_loading_text);
            FrameLayout frameLayout = (FrameLayout) window.findViewById(R.attr.ff_loading_dialog_container);
            this.ffLoadingContainer = frameLayout;
            frameLayout.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.dialogs.LoadingDialog.1
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    if (LoadingDialog.this.delegate != null) {
                        LoadingDialog.this.delegate.onClick();
                    }
                }
            });
        }
    }

    public void setLoadingText(CharSequence text) {
        TextView textView = this.tvLoadingView;
        if (textView != null) {
            textView.setText(text);
        }
    }
}
