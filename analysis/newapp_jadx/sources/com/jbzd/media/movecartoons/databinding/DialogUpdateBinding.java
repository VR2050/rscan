package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;
import io.github.armcha.autolink.AutoLinkTextView;

/* loaded from: classes2.dex */
public final class DialogUpdateBinding implements ViewBinding {

    @NonNull
    public final LinearLayout btnAccount;

    @NonNull
    public final TextView btnCancel;

    @NonNull
    public final TextView btnUpdate;

    @NonNull
    public final ImageView ivClose;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvSpaceMiddle;

    @NonNull
    public final AutoLinkTextView tvTips;

    private DialogUpdateBinding(@NonNull FrameLayout frameLayout, @NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull ImageView imageView, @NonNull TextView textView3, @NonNull AutoLinkTextView autoLinkTextView) {
        this.rootView = frameLayout;
        this.btnAccount = linearLayout;
        this.btnCancel = textView;
        this.btnUpdate = textView2;
        this.ivClose = imageView;
        this.tvSpaceMiddle = textView3;
        this.tvTips = autoLinkTextView;
    }

    @NonNull
    public static DialogUpdateBinding bind(@NonNull View view) {
        int i2 = R.id.btnAccount;
        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.btnAccount);
        if (linearLayout != null) {
            i2 = R.id.btnCancel;
            TextView textView = (TextView) view.findViewById(R.id.btnCancel);
            if (textView != null) {
                i2 = R.id.btnUpdate;
                TextView textView2 = (TextView) view.findViewById(R.id.btnUpdate);
                if (textView2 != null) {
                    i2 = R.id.iv_close;
                    ImageView imageView = (ImageView) view.findViewById(R.id.iv_close);
                    if (imageView != null) {
                        i2 = R.id.tv_space_middle;
                        TextView textView3 = (TextView) view.findViewById(R.id.tv_space_middle);
                        if (textView3 != null) {
                            i2 = R.id.tvTips;
                            AutoLinkTextView autoLinkTextView = (AutoLinkTextView) view.findViewById(R.id.tvTips);
                            if (autoLinkTextView != null) {
                                return new DialogUpdateBinding((FrameLayout) view, linearLayout, textView, textView2, imageView, textView3, autoLinkTextView);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogUpdateBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogUpdateBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_update, viewGroup, false);
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
