package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.SurfaceView;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.king.zxing.ViewfinderView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActScanBinding implements ViewBinding {

    @NonNull
    public final RelativeLayout btnTitleBack;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    public final ImageView ivTorch;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final SurfaceView surfaceView;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final ViewfinderView viewfinderView;

    private ActScanBinding(@NonNull LinearLayout linearLayout, @NonNull RelativeLayout relativeLayout, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull SurfaceView surfaceView, @NonNull TextView textView, @NonNull ViewfinderView viewfinderView) {
        this.rootView = linearLayout;
        this.btnTitleBack = relativeLayout;
        this.ivTitleLeftIcon = imageView;
        this.ivTorch = imageView2;
        this.surfaceView = surfaceView;
        this.tvTitle = textView;
        this.viewfinderView = viewfinderView;
    }

    @NonNull
    public static ActScanBinding bind(@NonNull View view) {
        int i2 = R.id.btn_titleBack;
        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.btn_titleBack);
        if (relativeLayout != null) {
            i2 = R.id.iv_titleLeftIcon;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
            if (imageView != null) {
                i2 = R.id.ivTorch;
                ImageView imageView2 = (ImageView) view.findViewById(R.id.ivTorch);
                if (imageView2 != null) {
                    i2 = R.id.surfaceView;
                    SurfaceView surfaceView = (SurfaceView) view.findViewById(R.id.surfaceView);
                    if (surfaceView != null) {
                        i2 = R.id.tv_title;
                        TextView textView = (TextView) view.findViewById(R.id.tv_title);
                        if (textView != null) {
                            i2 = R.id.viewfinderView;
                            ViewfinderView viewfinderView = (ViewfinderView) view.findViewById(R.id.viewfinderView);
                            if (viewfinderView != null) {
                                return new ActScanBinding((LinearLayout) view, relativeLayout, imageView, imageView2, surfaceView, textView, viewfinderView);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActScanBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActScanBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_scan, viewGroup, false);
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
