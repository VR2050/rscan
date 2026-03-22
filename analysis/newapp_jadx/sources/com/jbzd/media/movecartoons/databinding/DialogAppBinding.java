package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogAppBinding implements ViewBinding {

    @NonNull
    public final ImageView ivCancel;

    @NonNull
    private final FrameLayout rootView;

    /* renamed from: rv */
    @NonNull
    public final RecyclerView f10051rv;

    private DialogAppBinding(@NonNull FrameLayout frameLayout, @NonNull ImageView imageView, @NonNull RecyclerView recyclerView) {
        this.rootView = frameLayout;
        this.ivCancel = imageView;
        this.f10051rv = recyclerView;
    }

    @NonNull
    public static DialogAppBinding bind(@NonNull View view) {
        int i2 = R.id.iv_cancel;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_cancel);
        if (imageView != null) {
            i2 = R.id.f13003rv;
            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.f13003rv);
            if (recyclerView != null) {
                return new DialogAppBinding((FrameLayout) view, imageView, recyclerView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogAppBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogAppBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_app, viewGroup, false);
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
