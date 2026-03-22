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
public final class DialogRuleBinding implements ViewBinding {

    @NonNull
    public final FrameLayout close;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvTips;

    private DialogRuleBinding(@NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2, @NonNull TextView textView) {
        this.rootView = frameLayout;
        this.close = frameLayout2;
        this.tvTips = textView;
    }

    @NonNull
    public static DialogRuleBinding bind(@NonNull View view) {
        int i2 = R.id.close;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.close);
        if (frameLayout != null) {
            i2 = R.id.tvTips;
            TextView textView = (TextView) view.findViewById(R.id.tvTips);
            if (textView != null) {
                return new DialogRuleBinding((FrameLayout) view, frameLayout, textView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogRuleBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogRuleBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_rule, viewGroup, false);
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
