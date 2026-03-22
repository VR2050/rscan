package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogPortraitTypeBinding implements ViewBinding {

    @NonNull
    public final LinearLayout llCard;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvLocal;

    @NonNull
    public final TextView tvSystem;

    private DialogPortraitTypeBinding(@NonNull FrameLayout frameLayout, @NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = frameLayout;
        this.llCard = linearLayout;
        this.tvLocal = textView;
        this.tvSystem = textView2;
    }

    @NonNull
    public static DialogPortraitTypeBinding bind(@NonNull View view) {
        int i2 = R.id.ll_card;
        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_card);
        if (linearLayout != null) {
            i2 = R.id.tv_local;
            TextView textView = (TextView) view.findViewById(R.id.tv_local);
            if (textView != null) {
                i2 = R.id.tv_system;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_system);
                if (textView2 != null) {
                    return new DialogPortraitTypeBinding((FrameLayout) view, linearLayout, textView, textView2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogPortraitTypeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogPortraitTypeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_portrait_type, viewGroup, false);
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
