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
public final class ItemSingleChooseBinding implements ViewBinding {

    @NonNull
    public final FrameLayout frContainer;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvContent;

    private ItemSingleChooseBinding(@NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2, @NonNull TextView textView) {
        this.rootView = frameLayout;
        this.frContainer = frameLayout2;
        this.tvContent = textView;
    }

    @NonNull
    public static ItemSingleChooseBinding bind(@NonNull View view) {
        FrameLayout frameLayout = (FrameLayout) view;
        TextView textView = (TextView) view.findViewById(R.id.tv_content);
        if (textView != null) {
            return new ItemSingleChooseBinding((FrameLayout) view, frameLayout, textView);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.tv_content)));
    }

    @NonNull
    public static ItemSingleChooseBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemSingleChooseBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_single_choose, viewGroup, false);
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
