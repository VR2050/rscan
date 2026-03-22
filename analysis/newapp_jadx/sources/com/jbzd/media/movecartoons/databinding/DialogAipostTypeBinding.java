package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogAipostTypeBinding implements ViewBinding {

    @NonNull
    public final TextView btnCancel;

    @NonNull
    public final ImageView imgPosttypeGetvideo;

    @NonNull
    public final ImageView imgPosttypeMicrotnaot;

    @NonNull
    public final ImageView imgPosttypePost;

    @NonNull
    public final ImageView imgPosttypeVideos;

    @NonNull
    public final TextView itvBalance;

    @NonNull
    public final ImageView ivPosttypeCancel;

    @NonNull
    public final LinearLayout llDialogPostaitypeCanvas;

    @NonNull
    public final LinearLayout llDialogPostaitypeChangeface;

    @NonNull
    public final LinearLayout llDialogPostaitypeClearcloseth;

    @NonNull
    public final LinearLayout llDialogPostaitypePost;

    @NonNull
    private final LinearLayout rootView;

    private DialogAipostTypeBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull ImageView imageView3, @NonNull ImageView imageView4, @NonNull TextView textView2, @NonNull ImageView imageView5, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5) {
        this.rootView = linearLayout;
        this.btnCancel = textView;
        this.imgPosttypeGetvideo = imageView;
        this.imgPosttypeMicrotnaot = imageView2;
        this.imgPosttypePost = imageView3;
        this.imgPosttypeVideos = imageView4;
        this.itvBalance = textView2;
        this.ivPosttypeCancel = imageView5;
        this.llDialogPostaitypeCanvas = linearLayout2;
        this.llDialogPostaitypeChangeface = linearLayout3;
        this.llDialogPostaitypeClearcloseth = linearLayout4;
        this.llDialogPostaitypePost = linearLayout5;
    }

    @NonNull
    public static DialogAipostTypeBinding bind(@NonNull View view) {
        int i2 = R.id.btn_cancel;
        TextView textView = (TextView) view.findViewById(R.id.btn_cancel);
        if (textView != null) {
            i2 = R.id.img_posttype_getvideo;
            ImageView imageView = (ImageView) view.findViewById(R.id.img_posttype_getvideo);
            if (imageView != null) {
                i2 = R.id.img_posttype_microtnaot;
                ImageView imageView2 = (ImageView) view.findViewById(R.id.img_posttype_microtnaot);
                if (imageView2 != null) {
                    i2 = R.id.img_posttype_post;
                    ImageView imageView3 = (ImageView) view.findViewById(R.id.img_posttype_post);
                    if (imageView3 != null) {
                        i2 = R.id.img_posttype_videos;
                        ImageView imageView4 = (ImageView) view.findViewById(R.id.img_posttype_videos);
                        if (imageView4 != null) {
                            i2 = R.id.itv_balance;
                            TextView textView2 = (TextView) view.findViewById(R.id.itv_balance);
                            if (textView2 != null) {
                                i2 = R.id.iv_posttype_cancel;
                                ImageView imageView5 = (ImageView) view.findViewById(R.id.iv_posttype_cancel);
                                if (imageView5 != null) {
                                    i2 = R.id.ll_dialog_postaitype_canvas;
                                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_dialog_postaitype_canvas);
                                    if (linearLayout != null) {
                                        i2 = R.id.ll_dialog_postaitype_changeface;
                                        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_dialog_postaitype_changeface);
                                        if (linearLayout2 != null) {
                                            i2 = R.id.ll_dialog_postaitype_clearcloseth;
                                            LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_dialog_postaitype_clearcloseth);
                                            if (linearLayout3 != null) {
                                                i2 = R.id.ll_dialog_postaitype_post;
                                                LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.ll_dialog_postaitype_post);
                                                if (linearLayout4 != null) {
                                                    return new DialogAipostTypeBinding((LinearLayout) view, textView, imageView, imageView2, imageView3, imageView4, textView2, imageView5, linearLayout, linearLayout2, linearLayout3, linearLayout4);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogAipostTypeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogAipostTypeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_aipost_type, viewGroup, false);
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
