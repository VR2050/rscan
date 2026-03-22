package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemAppstoreBinding implements ViewBinding {

    @NonNull
    public final TextView btnDownload;

    @NonNull
    public final ImageView ivCoverAppitem;

    @NonNull
    public final ConstraintLayout llApp;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final TextView tvAppstoreAppname;

    @NonNull
    public final TextView tvAppstoreDes;

    @NonNull
    public final TextView tvClickNum;

    private ItemAppstoreBinding(@NonNull ConstraintLayout constraintLayout, @NonNull TextView textView, @NonNull ImageView imageView, @NonNull ConstraintLayout constraintLayout2, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = constraintLayout;
        this.btnDownload = textView;
        this.ivCoverAppitem = imageView;
        this.llApp = constraintLayout2;
        this.tvAppstoreAppname = textView2;
        this.tvAppstoreDes = textView3;
        this.tvClickNum = textView4;
    }

    @NonNull
    public static ItemAppstoreBinding bind(@NonNull View view) {
        int i2 = R.id.btnDownload;
        TextView textView = (TextView) view.findViewById(R.id.btnDownload);
        if (textView != null) {
            i2 = R.id.iv_cover_appitem;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_cover_appitem);
            if (imageView != null) {
                ConstraintLayout constraintLayout = (ConstraintLayout) view;
                i2 = R.id.tv_appstore_appname;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_appstore_appname);
                if (textView2 != null) {
                    i2 = R.id.tv_appstore_des;
                    TextView textView3 = (TextView) view.findViewById(R.id.tv_appstore_des);
                    if (textView3 != null) {
                        i2 = R.id.tv_click_num;
                        TextView textView4 = (TextView) view.findViewById(R.id.tv_click_num);
                        if (textView4 != null) {
                            return new ItemAppstoreBinding(constraintLayout, textView, imageView, constraintLayout, textView2, textView3, textView4);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemAppstoreBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemAppstoreBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_appstore, viewGroup, false);
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
