package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragDarkTradeBinding implements ViewBinding {

    @NonNull
    public final TextView fabAdd;

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    public final FrameLayout fragTag;

    @NonNull
    public final ImageView ivTag;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final RecyclerView rvType;

    private FragDarkTradeBinding(@NonNull ConstraintLayout constraintLayout, @NonNull TextView textView, @NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2, @NonNull ImageView imageView, @NonNull RecyclerView recyclerView) {
        this.rootView = constraintLayout;
        this.fabAdd = textView;
        this.fragContent = frameLayout;
        this.fragTag = frameLayout2;
        this.ivTag = imageView;
        this.rvType = recyclerView;
    }

    @NonNull
    public static FragDarkTradeBinding bind(@NonNull View view) {
        int i2 = R.id.fab_add;
        TextView textView = (TextView) view.findViewById(R.id.fab_add);
        if (textView != null) {
            i2 = R.id.frag_content;
            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_content);
            if (frameLayout != null) {
                i2 = R.id.frag_Tag;
                FrameLayout frameLayout2 = (FrameLayout) view.findViewById(R.id.frag_Tag);
                if (frameLayout2 != null) {
                    i2 = R.id.iv_tag;
                    ImageView imageView = (ImageView) view.findViewById(R.id.iv_tag);
                    if (imageView != null) {
                        i2 = R.id.rv_type;
                        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_type);
                        if (recyclerView != null) {
                            return new FragDarkTradeBinding((ConstraintLayout) view, textView, frameLayout, frameLayout2, imageView, recyclerView);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragDarkTradeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragDarkTradeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_dark_trade, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public ConstraintLayout getRoot() {
        return this.rootView;
    }
}
