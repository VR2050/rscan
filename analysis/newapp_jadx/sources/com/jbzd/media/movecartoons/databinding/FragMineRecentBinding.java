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
public final class FragMineRecentBinding implements ViewBinding {

    @NonNull
    public final FrameLayout errorView;

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    private final RelativeLayout rootView;

    private FragMineRecentBinding(@NonNull RelativeLayout relativeLayout, @NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2) {
        this.rootView = relativeLayout;
        this.errorView = frameLayout;
        this.fragContent = frameLayout2;
    }

    @NonNull
    public static FragMineRecentBinding bind(@NonNull View view) {
        int i2 = R.id.error_view;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.error_view);
        if (frameLayout != null) {
            i2 = R.id.frag_content;
            FrameLayout frameLayout2 = (FrameLayout) view.findViewById(R.id.frag_content);
            if (frameLayout2 != null) {
                return new FragMineRecentBinding((RelativeLayout) view, frameLayout, frameLayout2);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragMineRecentBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragMineRecentBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_mine_recent, viewGroup, false);
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
