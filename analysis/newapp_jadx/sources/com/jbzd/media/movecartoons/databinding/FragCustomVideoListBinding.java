package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragCustomVideoListBinding implements ViewBinding {

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    private final RelativeLayout rootView;

    private FragCustomVideoListBinding(@NonNull RelativeLayout relativeLayout, @NonNull FrameLayout frameLayout) {
        this.rootView = relativeLayout;
        this.fragContent = frameLayout;
    }

    @NonNull
    public static FragCustomVideoListBinding bind(@NonNull View view) {
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_content);
        if (frameLayout != null) {
            return new FragCustomVideoListBinding((RelativeLayout) view, frameLayout);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.frag_content)));
    }

    @NonNull
    public static FragCustomVideoListBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragCustomVideoListBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_custom_video_list, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public RelativeLayout getRoot() {
        return this.rootView;
    }
}
