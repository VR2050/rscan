package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.content.Context;
import android.text.TextUtils;
import android.view.Display;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public class XAlertDialog {
    private TextView btn_neg;
    private TextView btn_pos;
    private Context context;
    private Dialog dialog;
    private Display display;
    private ImageView img_line;
    private LinearLayout lLayout_bg;
    private TextView txt_msg;
    private TextView txt_title;
    private boolean showTitle = false;
    private boolean showMsg = false;
    private boolean showPosBtn = false;
    private boolean showNegBtn = false;

    public XAlertDialog(Context context) {
        this.context = context;
        this.display = ((WindowManager) context.getSystemService("window")).getDefaultDisplay();
    }

    private void setLayout() {
        if (!this.showTitle && !this.showMsg) {
            this.txt_title.setText("");
            this.txt_title.setVisibility(0);
        }
        if (this.showTitle) {
            this.txt_title.setVisibility(0);
        }
        if (this.showMsg) {
            this.txt_msg.setVisibility(0);
        }
        if (!this.showPosBtn && !this.showNegBtn) {
            this.btn_pos.setText("");
            this.btn_pos.setVisibility(0);
            this.btn_pos.setBackgroundResource(R.drawable.alert_dialog_selector);
            this.btn_pos.setOnClickListener(new View.OnClickListener() { // from class: com.jbzd.media.movecartoons.ui.dialog.XAlertDialog.3
                @Override // android.view.View.OnClickListener
                public void onClick(View view) {
                    XAlertDialog.this.dismiss();
                }
            });
        }
        if (this.showPosBtn && this.showNegBtn) {
            this.btn_pos.setVisibility(0);
            this.btn_pos.setBackgroundResource(R.drawable.alert_dialog_right_selector);
            this.btn_neg.setVisibility(0);
            this.btn_neg.setBackgroundResource(R.drawable.alert_dialog_left_selector);
            this.img_line.setVisibility(0);
        }
        if (this.showPosBtn && !this.showNegBtn) {
            this.btn_pos.setVisibility(0);
            this.btn_pos.setBackgroundResource(R.drawable.alert_dialog_selector);
        }
        if (this.showPosBtn || !this.showNegBtn) {
            return;
        }
        this.btn_neg.setVisibility(0);
        this.btn_neg.setBackgroundResource(R.drawable.alert_dialog_selector);
    }

    public XAlertDialog builder() {
        View inflate = LayoutInflater.from(this.context).inflate(R.layout.view_alert_dialog, (ViewGroup) null);
        this.lLayout_bg = (LinearLayout) inflate.findViewById(R.id.lLayout_bg);
        this.txt_title = (TextView) inflate.findViewById(R.id.txt_num_click);
        this.txt_msg = (TextView) inflate.findViewById(R.id.txt_msg);
        this.btn_neg = (TextView) inflate.findViewById(R.id.btn_neg);
        this.btn_pos = (TextView) inflate.findViewById(R.id.btn_pos);
        this.img_line = (ImageView) inflate.findViewById(R.id.img_line);
        setGone();
        Dialog dialog = new Dialog(this.context, R.style.AlertDialogStyle);
        this.dialog = dialog;
        dialog.setContentView(inflate);
        this.lLayout_bg.setLayoutParams(new FrameLayout.LayoutParams((int) ((this.display.getWidth() > this.display.getHeight() ? this.display.getHeight() : this.display.getWidth()) * 0.71d), -2));
        return this;
    }

    public void dismiss() {
        Dialog dialog = this.dialog;
        if (dialog != null) {
            dialog.dismiss();
        }
    }

    public boolean isShowing() {
        Dialog dialog = this.dialog;
        return dialog != null && dialog.isShowing();
    }

    public XAlertDialog setCancelable(boolean z) {
        this.dialog.setCancelable(z);
        return this;
    }

    public XAlertDialog setGone() {
        if (this.lLayout_bg != null) {
            this.txt_title.setVisibility(8);
            this.txt_msg.setVisibility(8);
            this.btn_neg.setVisibility(8);
            this.btn_pos.setVisibility(8);
            this.img_line.setVisibility(8);
        }
        this.showTitle = false;
        this.showMsg = false;
        this.showPosBtn = false;
        this.showNegBtn = false;
        return this;
    }

    public XAlertDialog setMsg(String str) {
        this.showMsg = true;
        if (TextUtils.isEmpty(str)) {
            this.txt_msg.setText("");
        } else {
            this.txt_msg.setText(str);
        }
        return this;
    }

    public XAlertDialog setNegativeButton(String str, View.OnClickListener onClickListener) {
        return setNegativeButton(str, -1, onClickListener);
    }

    public XAlertDialog setPositiveButton(String str, View.OnClickListener onClickListener) {
        return setPositiveButton(str, -1, onClickListener);
    }

    public XAlertDialog setTitle(String str) {
        this.showTitle = true;
        if (TextUtils.isEmpty(str)) {
            this.txt_title.setText("提示");
        } else {
            this.txt_title.setText(str);
        }
        return this;
    }

    public void show() {
        setLayout();
        this.dialog.show();
    }

    public XAlertDialog setNegativeButton(String str, int i2, final View.OnClickListener onClickListener) {
        this.showNegBtn = true;
        if ("".equals(str)) {
            this.btn_neg.setText("");
        } else {
            this.btn_neg.setText(str);
        }
        this.btn_neg.setOnClickListener(new View.OnClickListener() { // from class: com.jbzd.media.movecartoons.ui.dialog.XAlertDialog.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                View.OnClickListener onClickListener2 = onClickListener;
                if (onClickListener2 != null) {
                    onClickListener2.onClick(view);
                }
                XAlertDialog.this.dismiss();
            }
        });
        return this;
    }

    public XAlertDialog setPositiveButton(String str, int i2, final View.OnClickListener onClickListener) {
        this.showPosBtn = true;
        if ("".equals(str)) {
            this.btn_pos.setText("");
        } else {
            this.btn_pos.setText(str);
        }
        this.btn_pos.setOnClickListener(new View.OnClickListener() { // from class: com.jbzd.media.movecartoons.ui.dialog.XAlertDialog.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                View.OnClickListener onClickListener2 = onClickListener;
                if (onClickListener2 != null) {
                    onClickListener2.onClick(view);
                }
                XAlertDialog.this.dismiss();
            }
        });
        return this;
    }
}
