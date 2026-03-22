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
import io.github.armcha.autolink.AutoLinkTextView;

/* loaded from: classes2.dex */
public final class DialogNoticeBinding implements ViewBinding {

    @NonNull
    public final TextView btn;

    @NonNull
    public final TextView btnAppStore;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final AutoLinkTextView tvTips;

    private DialogNoticeBinding(@NonNull FrameLayout frameLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull AutoLinkTextView autoLinkTextView) {
        this.rootView = frameLayout;
        this.btn = textView;
        this.btnAppStore = textView2;
        this.tvTips = autoLinkTextView;
    }

    @NonNull
    public static DialogNoticeBinding bind(@NonNull View view) {
        int i2 = R.id.btn;
        TextView textView = (TextView) view.findViewById(R.id.btn);
        if (textView != null) {
            i2 = R.id.btnAppStore;
            TextView textView2 = (TextView) view.findViewById(R.id.btnAppStore);
            if (textView2 != null) {
                i2 = R.id.tvTips;
                AutoLinkTextView autoLinkTextView = (AutoLinkTextView) view.findViewById(R.id.tvTips);
                if (autoLinkTextView != null) {
                    return new DialogNoticeBinding((FrameLayout) view, textView, textView2, autoLinkTextView);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogNoticeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogNoticeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_notice, viewGroup, false);
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
