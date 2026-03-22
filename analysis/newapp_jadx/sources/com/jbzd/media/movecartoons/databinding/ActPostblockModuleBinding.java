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
public final class ActPostblockModuleBinding implements ViewBinding {

    @NonNull
    public final TextView btnCreateCircle;

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    private final LinearLayout rootView;

    private ActPostblockModuleBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull FrameLayout frameLayout) {
        this.rootView = linearLayout;
        this.btnCreateCircle = textView;
        this.fragContent = frameLayout;
    }

    @NonNull
    public static ActPostblockModuleBinding bind(@NonNull View view) {
        int i2 = R.id.btn_create_circle;
        TextView textView = (TextView) view.findViewById(R.id.btn_create_circle);
        if (textView != null) {
            i2 = R.id.frag_content;
            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_content);
            if (frameLayout != null) {
                return new ActPostblockModuleBinding((LinearLayout) view, textView, frameLayout);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActPostblockModuleBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActPostblockModuleBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_postblock_module, viewGroup, false);
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
