package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ViewAlertDialogBinding implements ViewBinding {

    @NonNull
    public final TextView btnNeg;

    @NonNull
    public final TextView btnPos;

    @NonNull
    public final ImageView imgLine;

    @NonNull
    public final LinearLayout lLayoutBg;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView txtMsg;

    @NonNull
    public final TextView txtNumClick;

    private ViewAlertDialogBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = linearLayout;
        this.btnNeg = textView;
        this.btnPos = textView2;
        this.imgLine = imageView;
        this.lLayoutBg = linearLayout2;
        this.txtMsg = textView3;
        this.txtNumClick = textView4;
    }

    @NonNull
    public static ViewAlertDialogBinding bind(@NonNull View view) {
        int i2 = R.id.btn_neg;
        TextView textView = (TextView) view.findViewById(R.id.btn_neg);
        if (textView != null) {
            i2 = R.id.btn_pos;
            TextView textView2 = (TextView) view.findViewById(R.id.btn_pos);
            if (textView2 != null) {
                i2 = R.id.img_line;
                ImageView imageView = (ImageView) view.findViewById(R.id.img_line);
                if (imageView != null) {
                    LinearLayout linearLayout = (LinearLayout) view;
                    i2 = R.id.txt_msg;
                    TextView textView3 = (TextView) view.findViewById(R.id.txt_msg);
                    if (textView3 != null) {
                        i2 = R.id.txt_num_click;
                        TextView textView4 = (TextView) view.findViewById(R.id.txt_num_click);
                        if (textView4 != null) {
                            return new ViewAlertDialogBinding(linearLayout, textView, textView2, imageView, linearLayout, textView3, textView4);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ViewAlertDialogBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ViewAlertDialogBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.view_alert_dialog, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayout getRoot() {
        return this.rootView;
    }
}
