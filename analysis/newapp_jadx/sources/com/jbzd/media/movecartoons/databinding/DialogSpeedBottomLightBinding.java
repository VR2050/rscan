package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatButton;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogSpeedBottomLightBinding implements ViewBinding {

    @NonNull
    public final AppCompatButton btnSaveSure;

    @NonNull
    public final ImageView close;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final LinearLayout speedBtn1;

    @NonNull
    public final LinearLayout speedBtn2;

    @NonNull
    public final LinearLayout speedBtn3;

    @NonNull
    public final LinearLayout speedBtn4;

    @NonNull
    public final LinearLayout speedBtn5;

    @NonNull
    public final TextView speedDescribe1;

    @NonNull
    public final TextView speedDescribe2;

    @NonNull
    public final TextView speedDescribe3;

    @NonNull
    public final TextView speedDescribe4;

    @NonNull
    public final TextView speedDescribe5;

    @NonNull
    public final ImageView speedImg1;

    @NonNull
    public final ImageView speedImg2;

    @NonNull
    public final ImageView speedImg3;

    @NonNull
    public final ImageView speedImg4;

    @NonNull
    public final ImageView speedImg5;

    @NonNull
    public final TextView speedText1;

    @NonNull
    public final TextView speedText2;

    @NonNull
    public final TextView speedText3;

    @NonNull
    public final TextView speedText4;

    @NonNull
    public final TextView speedText5;

    private DialogSpeedBottomLightBinding(@NonNull LinearLayout linearLayout, @NonNull AppCompatButton appCompatButton, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5, @NonNull LinearLayout linearLayout6, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull ImageView imageView2, @NonNull ImageView imageView3, @NonNull ImageView imageView4, @NonNull ImageView imageView5, @NonNull ImageView imageView6, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull TextView textView8, @NonNull TextView textView9, @NonNull TextView textView10) {
        this.rootView = linearLayout;
        this.btnSaveSure = appCompatButton;
        this.close = imageView;
        this.speedBtn1 = linearLayout2;
        this.speedBtn2 = linearLayout3;
        this.speedBtn3 = linearLayout4;
        this.speedBtn4 = linearLayout5;
        this.speedBtn5 = linearLayout6;
        this.speedDescribe1 = textView;
        this.speedDescribe2 = textView2;
        this.speedDescribe3 = textView3;
        this.speedDescribe4 = textView4;
        this.speedDescribe5 = textView5;
        this.speedImg1 = imageView2;
        this.speedImg2 = imageView3;
        this.speedImg3 = imageView4;
        this.speedImg4 = imageView5;
        this.speedImg5 = imageView6;
        this.speedText1 = textView6;
        this.speedText2 = textView7;
        this.speedText3 = textView8;
        this.speedText4 = textView9;
        this.speedText5 = textView10;
    }

    @NonNull
    public static DialogSpeedBottomLightBinding bind(@NonNull View view) {
        int i2 = R.id.btn_save_sure;
        AppCompatButton appCompatButton = (AppCompatButton) view.findViewById(R.id.btn_save_sure);
        if (appCompatButton != null) {
            i2 = R.id.close;
            ImageView imageView = (ImageView) view.findViewById(R.id.close);
            if (imageView != null) {
                i2 = R.id.speed_btn1;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.speed_btn1);
                if (linearLayout != null) {
                    i2 = R.id.speed_btn2;
                    LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.speed_btn2);
                    if (linearLayout2 != null) {
                        i2 = R.id.speed_btn3;
                        LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.speed_btn3);
                        if (linearLayout3 != null) {
                            i2 = R.id.speed_btn4;
                            LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.speed_btn4);
                            if (linearLayout4 != null) {
                                i2 = R.id.speed_btn5;
                                LinearLayout linearLayout5 = (LinearLayout) view.findViewById(R.id.speed_btn5);
                                if (linearLayout5 != null) {
                                    i2 = R.id.speed_describe1;
                                    TextView textView = (TextView) view.findViewById(R.id.speed_describe1);
                                    if (textView != null) {
                                        i2 = R.id.speed_describe2;
                                        TextView textView2 = (TextView) view.findViewById(R.id.speed_describe2);
                                        if (textView2 != null) {
                                            i2 = R.id.speed_describe3;
                                            TextView textView3 = (TextView) view.findViewById(R.id.speed_describe3);
                                            if (textView3 != null) {
                                                i2 = R.id.speed_describe4;
                                                TextView textView4 = (TextView) view.findViewById(R.id.speed_describe4);
                                                if (textView4 != null) {
                                                    i2 = R.id.speed_describe5;
                                                    TextView textView5 = (TextView) view.findViewById(R.id.speed_describe5);
                                                    if (textView5 != null) {
                                                        i2 = R.id.speed_img1;
                                                        ImageView imageView2 = (ImageView) view.findViewById(R.id.speed_img1);
                                                        if (imageView2 != null) {
                                                            i2 = R.id.speed_img2;
                                                            ImageView imageView3 = (ImageView) view.findViewById(R.id.speed_img2);
                                                            if (imageView3 != null) {
                                                                i2 = R.id.speed_img3;
                                                                ImageView imageView4 = (ImageView) view.findViewById(R.id.speed_img3);
                                                                if (imageView4 != null) {
                                                                    i2 = R.id.speed_img4;
                                                                    ImageView imageView5 = (ImageView) view.findViewById(R.id.speed_img4);
                                                                    if (imageView5 != null) {
                                                                        i2 = R.id.speed_img5;
                                                                        ImageView imageView6 = (ImageView) view.findViewById(R.id.speed_img5);
                                                                        if (imageView6 != null) {
                                                                            i2 = R.id.speed_text1;
                                                                            TextView textView6 = (TextView) view.findViewById(R.id.speed_text1);
                                                                            if (textView6 != null) {
                                                                                i2 = R.id.speed_text2;
                                                                                TextView textView7 = (TextView) view.findViewById(R.id.speed_text2);
                                                                                if (textView7 != null) {
                                                                                    i2 = R.id.speed_text3;
                                                                                    TextView textView8 = (TextView) view.findViewById(R.id.speed_text3);
                                                                                    if (textView8 != null) {
                                                                                        i2 = R.id.speed_text4;
                                                                                        TextView textView9 = (TextView) view.findViewById(R.id.speed_text4);
                                                                                        if (textView9 != null) {
                                                                                            i2 = R.id.speed_text5;
                                                                                            TextView textView10 = (TextView) view.findViewById(R.id.speed_text5);
                                                                                            if (textView10 != null) {
                                                                                                return new DialogSpeedBottomLightBinding((LinearLayout) view, appCompatButton, imageView, linearLayout, linearLayout2, linearLayout3, linearLayout4, linearLayout5, textView, textView2, textView3, textView4, textView5, imageView2, imageView3, imageView4, imageView5, imageView6, textView6, textView7, textView8, textView9, textView10);
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
    public static DialogSpeedBottomLightBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogSpeedBottomLightBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_speed_bottom_light, viewGroup, false);
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
