package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.noober.background.view.BLConstraintLayout;
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ViewAdBottomBarBinding implements ViewBinding {

    @NonNull
    public final BLConstraintLayout adRoot;

    @NonNull
    public final BLTextView btnVip;

    @NonNull
    public final ImageView ivClose;

    @NonNull
    public final ImageView ivCover;

    @NonNull
    private final BLConstraintLayout rootView;

    @NonNull
    public final TextView tvSub;

    @NonNull
    public final TextView tvTitle;

    private ViewAdBottomBarBinding(@NonNull BLConstraintLayout bLConstraintLayout, @NonNull BLConstraintLayout bLConstraintLayout2, @NonNull BLTextView bLTextView, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = bLConstraintLayout;
        this.adRoot = bLConstraintLayout2;
        this.btnVip = bLTextView;
        this.ivClose = imageView;
        this.ivCover = imageView2;
        this.tvSub = textView;
        this.tvTitle = textView2;
    }

    @NonNull
    public static ViewAdBottomBarBinding bind(@NonNull View view) {
        BLConstraintLayout bLConstraintLayout = (BLConstraintLayout) view;
        int i2 = R.id.btnVip;
        BLTextView bLTextView = (BLTextView) view.findViewById(R.id.btnVip);
        if (bLTextView != null) {
            i2 = R.id.ivClose;
            ImageView imageView = (ImageView) view.findViewById(R.id.ivClose);
            if (imageView != null) {
                i2 = R.id.ivCover;
                ImageView imageView2 = (ImageView) view.findViewById(R.id.ivCover);
                if (imageView2 != null) {
                    i2 = R.id.tvSub;
                    TextView textView = (TextView) view.findViewById(R.id.tvSub);
                    if (textView != null) {
                        i2 = R.id.tvTitle;
                        TextView textView2 = (TextView) view.findViewById(R.id.tvTitle);
                        if (textView2 != null) {
                            return new ViewAdBottomBarBinding((BLConstraintLayout) view, bLConstraintLayout, bLTextView, imageView, imageView2, textView, textView2);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ViewAdBottomBarBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ViewAdBottomBarBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.view_ad_bottom_bar, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public BLConstraintLayout getRoot() {
        return this.rootView;
    }
}
