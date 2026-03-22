package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogActivityReminderBinding implements ViewBinding {

    @NonNull
    public final ImageView ivCancel;

    @NonNull
    public final ImageView ivPromotionalGraphics;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvListAdImg;

    private DialogActivityReminderBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull RecyclerView recyclerView) {
        this.rootView = linearLayout;
        this.ivCancel = imageView;
        this.ivPromotionalGraphics = imageView2;
        this.rvListAdImg = recyclerView;
    }

    @NonNull
    public static DialogActivityReminderBinding bind(@NonNull View view) {
        int i2 = R.id.iv_cancel;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_cancel);
        if (imageView != null) {
            i2 = R.id.iv_promotional_graphics;
            ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_promotional_graphics);
            if (imageView2 != null) {
                i2 = R.id.rv_list_adImg;
                RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_list_adImg);
                if (recyclerView != null) {
                    return new DialogActivityReminderBinding((LinearLayout) view, imageView, imageView2, recyclerView);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogActivityReminderBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogActivityReminderBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_activity_reminder, viewGroup, false);
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
