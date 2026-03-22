package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogNoticeBuyBinding implements ViewBinding {

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvBuyDialog;

    @NonNull
    public final TextView tvCancelDialog;

    @NonNull
    public final TextView tvDialogContent;

    private DialogNoticeBuyBinding(@NonNull FrameLayout frameLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = frameLayout;
        this.tvBuyDialog = textView;
        this.tvCancelDialog = textView2;
        this.tvDialogContent = textView3;
    }

    @NonNull
    public static DialogNoticeBuyBinding bind(@NonNull View view) {
        int i2 = R.id.tv_buy_dialog;
        TextView textView = (TextView) view.findViewById(R.id.tv_buy_dialog);
        if (textView != null) {
            i2 = R.id.tv_cancel_dialog;
            TextView textView2 = (TextView) view.findViewById(R.id.tv_cancel_dialog);
            if (textView2 != null) {
                i2 = R.id.tv_dialog_content;
                TextView textView3 = (TextView) view.findViewById(R.id.tv_dialog_content);
                if (textView3 != null) {
                    return new DialogNoticeBuyBinding((FrameLayout) view, textView, textView2, textView3);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogNoticeBuyBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogNoticeBuyBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_notice_buy, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
