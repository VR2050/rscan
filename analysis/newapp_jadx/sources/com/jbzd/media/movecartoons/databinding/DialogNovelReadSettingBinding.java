package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.RadioGroup;
import android.widget.SeekBar;
import android.widget.Switch;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.LinearLayoutCompat;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.MyRadioButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogNovelReadSettingBinding implements ViewBinding {

    @NonNull
    public final ImageView ivCloseNovelReadSetting;

    @NonNull
    public final SeekBar progressBrightness;

    @NonNull
    public final RadioGroup raGroupBackground;

    @NonNull
    public final MyRadioButton raNovelcolorFive;

    @NonNull
    public final MyRadioButton raNovelcolorFour;

    @NonNull
    public final MyRadioButton raNovelcolorOne;

    @NonNull
    public final MyRadioButton raNovelcolorThree;

    @NonNull
    public final MyRadioButton raNovelcolorTwo;

    @NonNull
    public final MyRadioButton rbNovelredDefault;

    @NonNull
    public final MyRadioButton rbNovelredFg;

    @NonNull
    public final MyRadioButton rbNovelredFz;

    @NonNull
    public final MyRadioButton rbNovelredPh;

    @NonNull
    public final MyRadioButton rbNovelredSx;

    @NonNull
    public final RadioGroup rgNav;

    @NonNull
    private final LinearLayoutCompat rootView;

    @NonNull
    public final Switch swSwitchModelDark;

    @NonNull
    public final TextView tvTextsizeBig;

    @NonNull
    public final TextView tvTextsizeSmall;

    @NonNull
    public final TextView tvTextsizeValue;

    private DialogNovelReadSettingBinding(@NonNull LinearLayoutCompat linearLayoutCompat, @NonNull ImageView imageView, @NonNull SeekBar seekBar, @NonNull RadioGroup radioGroup, @NonNull MyRadioButton myRadioButton, @NonNull MyRadioButton myRadioButton2, @NonNull MyRadioButton myRadioButton3, @NonNull MyRadioButton myRadioButton4, @NonNull MyRadioButton myRadioButton5, @NonNull MyRadioButton myRadioButton6, @NonNull MyRadioButton myRadioButton7, @NonNull MyRadioButton myRadioButton8, @NonNull MyRadioButton myRadioButton9, @NonNull MyRadioButton myRadioButton10, @NonNull RadioGroup radioGroup2, @NonNull Switch r18, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = linearLayoutCompat;
        this.ivCloseNovelReadSetting = imageView;
        this.progressBrightness = seekBar;
        this.raGroupBackground = radioGroup;
        this.raNovelcolorFive = myRadioButton;
        this.raNovelcolorFour = myRadioButton2;
        this.raNovelcolorOne = myRadioButton3;
        this.raNovelcolorThree = myRadioButton4;
        this.raNovelcolorTwo = myRadioButton5;
        this.rbNovelredDefault = myRadioButton6;
        this.rbNovelredFg = myRadioButton7;
        this.rbNovelredFz = myRadioButton8;
        this.rbNovelredPh = myRadioButton9;
        this.rbNovelredSx = myRadioButton10;
        this.rgNav = radioGroup2;
        this.swSwitchModelDark = r18;
        this.tvTextsizeBig = textView;
        this.tvTextsizeSmall = textView2;
        this.tvTextsizeValue = textView3;
    }

    @NonNull
    public static DialogNovelReadSettingBinding bind(@NonNull View view) {
        int i2 = R.id.iv_close_novel_read_setting;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_close_novel_read_setting);
        if (imageView != null) {
            i2 = R.id.progress_brightness;
            SeekBar seekBar = (SeekBar) view.findViewById(R.id.progress_brightness);
            if (seekBar != null) {
                i2 = R.id.ra_group_background;
                RadioGroup radioGroup = (RadioGroup) view.findViewById(R.id.ra_group_background);
                if (radioGroup != null) {
                    i2 = R.id.ra_novelcolor_five;
                    MyRadioButton myRadioButton = (MyRadioButton) view.findViewById(R.id.ra_novelcolor_five);
                    if (myRadioButton != null) {
                        i2 = R.id.ra_novelcolor_four;
                        MyRadioButton myRadioButton2 = (MyRadioButton) view.findViewById(R.id.ra_novelcolor_four);
                        if (myRadioButton2 != null) {
                            i2 = R.id.ra_novelcolor_one;
                            MyRadioButton myRadioButton3 = (MyRadioButton) view.findViewById(R.id.ra_novelcolor_one);
                            if (myRadioButton3 != null) {
                                i2 = R.id.ra_novelcolor_three;
                                MyRadioButton myRadioButton4 = (MyRadioButton) view.findViewById(R.id.ra_novelcolor_three);
                                if (myRadioButton4 != null) {
                                    i2 = R.id.ra_novelcolor_two;
                                    MyRadioButton myRadioButton5 = (MyRadioButton) view.findViewById(R.id.ra_novelcolor_two);
                                    if (myRadioButton5 != null) {
                                        i2 = R.id.rb_novelred_default;
                                        MyRadioButton myRadioButton6 = (MyRadioButton) view.findViewById(R.id.rb_novelred_default);
                                        if (myRadioButton6 != null) {
                                            i2 = R.id.rb_novelred_fg;
                                            MyRadioButton myRadioButton7 = (MyRadioButton) view.findViewById(R.id.rb_novelred_fg);
                                            if (myRadioButton7 != null) {
                                                i2 = R.id.rb_novelred_fz;
                                                MyRadioButton myRadioButton8 = (MyRadioButton) view.findViewById(R.id.rb_novelred_fz);
                                                if (myRadioButton8 != null) {
                                                    i2 = R.id.rb_novelred_ph;
                                                    MyRadioButton myRadioButton9 = (MyRadioButton) view.findViewById(R.id.rb_novelred_ph);
                                                    if (myRadioButton9 != null) {
                                                        i2 = R.id.rb_novelred_sx;
                                                        MyRadioButton myRadioButton10 = (MyRadioButton) view.findViewById(R.id.rb_novelred_sx);
                                                        if (myRadioButton10 != null) {
                                                            i2 = R.id.rg_nav;
                                                            RadioGroup radioGroup2 = (RadioGroup) view.findViewById(R.id.rg_nav);
                                                            if (radioGroup2 != null) {
                                                                i2 = R.id.sw_switch_model_dark;
                                                                Switch r19 = (Switch) view.findViewById(R.id.sw_switch_model_dark);
                                                                if (r19 != null) {
                                                                    i2 = R.id.tv_textsize_big;
                                                                    TextView textView = (TextView) view.findViewById(R.id.tv_textsize_big);
                                                                    if (textView != null) {
                                                                        i2 = R.id.tv_textsize_small;
                                                                        TextView textView2 = (TextView) view.findViewById(R.id.tv_textsize_small);
                                                                        if (textView2 != null) {
                                                                            i2 = R.id.tv_textsize_value;
                                                                            TextView textView3 = (TextView) view.findViewById(R.id.tv_textsize_value);
                                                                            if (textView3 != null) {
                                                                                return new DialogNovelReadSettingBinding((LinearLayoutCompat) view, imageView, seekBar, radioGroup, myRadioButton, myRadioButton2, myRadioButton3, myRadioButton4, myRadioButton5, myRadioButton6, myRadioButton7, myRadioButton8, myRadioButton9, myRadioButton10, radioGroup2, r19, textView, textView2, textView3);
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
    public static DialogNovelReadSettingBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogNovelReadSettingBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_novel_read_setting, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayoutCompat getRoot() {
        return this.rootView;
    }
}
