package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.Toolbar;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragFindBinding implements ViewBinding {

    @NonNull
    public final FrameLayout flTitle;

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final Toolbar toolbar;

    private FragFindBinding(@NonNull LinearLayout linearLayout, @NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2, @NonNull Toolbar toolbar) {
        this.rootView = linearLayout;
        this.flTitle = frameLayout;
        this.fragContent = frameLayout2;
        this.toolbar = toolbar;
    }

    @NonNull
    public static FragFindBinding bind(@NonNull View view) {
        int i2 = R.id.fl_title;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.fl_title);
        if (frameLayout != null) {
            i2 = R.id.frag_content;
            FrameLayout frameLayout2 = (FrameLayout) view.findViewById(R.id.frag_content);
            if (frameLayout2 != null) {
                i2 = R.id.toolbar;
                Toolbar toolbar = (Toolbar) view.findViewById(R.id.toolbar);
                if (toolbar != null) {
                    return new FragFindBinding((LinearLayout) view, frameLayout, frameLayout2, toolbar);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragFindBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragFindBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_find, viewGroup, false);
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
