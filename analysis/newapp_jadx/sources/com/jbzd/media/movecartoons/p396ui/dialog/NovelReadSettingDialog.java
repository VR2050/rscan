package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.RadioGroup;
import android.widget.SeekBar;
import android.widget.Switch;
import android.widget.TextView;
import androidx.appcompat.widget.ActivityChooserModel;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.jbzd.media.movecartoons.p396ui.dialog.NovelReadSettingDialog;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function4;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.C0885h;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000v\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\f\n\u0002\u0010\u0007\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\t\u0018\u00002\u00020\u00012\u00020\u0002Bi\u0012`\u0010D\u001a\\\u0012\u0013\u0012\u00110%¢\u0006\f\b>\u0012\b\b?\u0012\u0004\b\b(\u001f\u0012\u0013\u0012\u00110%¢\u0006\f\b>\u0012\b\b?\u0012\u0004\b\b(@\u0012\u0013\u0012\u00110\u0018¢\u0006\f\b>\u0012\b\b?\u0012\u0004\b\b(A\u0012\u0013\u0012\u00110B¢\u0006\f\b>\u0012\b\b?\u0012\u0004\b\b(C\u0012\u0004\u0012\u00020\u00050=¢\u0006\u0004\bZ\u0010[J\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u0019\u0010\n\u001a\u00020\u00052\b\u0010\t\u001a\u0004\u0018\u00010\bH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u0019\u0010\r\u001a\u00020\f2\b\u0010\t\u001a\u0004\u0018\u00010\bH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u0017\u0010\u0010\u001a\u00020\u00052\u0006\u0010\u000f\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0010\u0010\u0007R\"\u0010\u0012\u001a\u00020\u00118\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015\"\u0004\b\u0016\u0010\u0017R\"\u0010\u0019\u001a\u00020\u00188\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001c\"\u0004\b\u001d\u0010\u001eR\"\u0010\u001f\u001a\u00020\u00188\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001f\u0010\u001a\u001a\u0004\b \u0010\u001c\"\u0004\b!\u0010\u001eR\"\u0010\"\u001a\u00020\u00188\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\"\u0010\u001a\u001a\u0004\b#\u0010\u001c\"\u0004\b$\u0010\u001eR\"\u0010&\u001a\u00020%8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b&\u0010'\u001a\u0004\b(\u0010)\"\u0004\b*\u0010+R\"\u0010-\u001a\u00020,8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b-\u0010.\u001a\u0004\b/\u00100\"\u0004\b1\u00102R\"\u00104\u001a\u0002038\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b4\u00105\u001a\u0004\b6\u00107\"\u0004\b8\u00109R\"\u0010:\u001a\u00020,8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b:\u0010.\u001a\u0004\b;\u00100\"\u0004\b<\u00102Rp\u0010D\u001a\\\u0012\u0013\u0012\u00110%¢\u0006\f\b>\u0012\b\b?\u0012\u0004\b\b(\u001f\u0012\u0013\u0012\u00110%¢\u0006\f\b>\u0012\b\b?\u0012\u0004\b\b(@\u0012\u0013\u0012\u00110\u0018¢\u0006\f\b>\u0012\b\b?\u0012\u0004\b\b(A\u0012\u0013\u0012\u00110B¢\u0006\f\b>\u0012\b\b?\u0012\u0004\b\b(C\u0012\u0004\u0012\u00020\u00050=8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\bD\u0010ER\"\u0010G\u001a\u00020F8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\bG\u0010H\u001a\u0004\bI\u0010J\"\u0004\bK\u0010LR\"\u0010M\u001a\u00020B8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bM\u0010N\u001a\u0004\bO\u0010P\"\u0004\bQ\u0010RR\"\u0010T\u001a\u00020S8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\bT\u0010U\u001a\u0004\bV\u0010W\"\u0004\bX\u0010Y¨\u0006\\"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/NovelReadSettingDialog;", "Lcom/google/android/material/bottomsheet/BottomSheetDialogFragment;", "Landroid/view/View$OnClickListener;", "Landroid/view/View;", "contentView", "", "initContentView", "(Landroid/view/View;)V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "view", "onClick", "Landroid/app/Activity;", ActivityChooserModel.ATTRIBUTE_ACTIVITY, "Landroid/app/Activity;", "getActivity", "()Landroid/app/Activity;", "setActivity", "(Landroid/app/Activity;)V", "", "showProgress", "I", "getShowProgress", "()I", "setShowProgress", "(I)V", "textSize", "getTextSize", "setTextSize", "colorBgPosition", "getColorBgPosition", "setColorBgPosition", "", "windowBrightness", "F", "getWindowBrightness", "()F", "setWindowBrightness", "(F)V", "Landroid/widget/SeekBar;", "seekpar_auto_page", "Landroid/widget/SeekBar;", "getSeekpar_auto_page", "()Landroid/widget/SeekBar;", "setSeekpar_auto_page", "(Landroid/widget/SeekBar;)V", "Landroid/widget/TextView;", "tv_textsize_value", "Landroid/widget/TextView;", "getTv_textsize_value", "()Landroid/widget/TextView;", "setTv_textsize_value", "(Landroid/widget/TextView;)V", "progress_brightness", "getProgress_brightness", "setProgress_brightness", "Lkotlin/Function4;", "Lkotlin/ParameterName;", "name", "brightness", "colorPosition", "", "readModel", "callback", "Lkotlin/jvm/functions/Function4;", "Landroid/widget/ImageView;", "iv_close_novel_read_setting", "Landroid/widget/ImageView;", "getIv_close_novel_read_setting", "()Landroid/widget/ImageView;", "setIv_close_novel_read_setting", "(Landroid/widget/ImageView;)V", "readDarkModel", "Z", "getReadDarkModel", "()Z", "setReadDarkModel", "(Z)V", "Landroid/widget/RadioGroup;", "ra_group_background", "Landroid/widget/RadioGroup;", "getRa_group_background", "()Landroid/widget/RadioGroup;", "setRa_group_background", "(Landroid/widget/RadioGroup;)V", "<init>", "(Lkotlin/jvm/functions/Function4;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class NovelReadSettingDialog extends BottomSheetDialogFragment implements View.OnClickListener {
    public Activity activity;

    @NotNull
    private final Function4<Float, Float, Integer, Boolean, Unit> callback;
    private int colorBgPosition;
    public ImageView iv_close_novel_read_setting;
    public SeekBar progress_brightness;
    public RadioGroup ra_group_background;
    private boolean readDarkModel;
    public SeekBar seekpar_auto_page;
    private int showProgress;
    private int textSize;
    public TextView tv_textsize_value;
    private float windowBrightness;

    /* JADX WARN: Multi-variable type inference failed */
    public NovelReadSettingDialog(@NotNull Function4<? super Float, ? super Float, ? super Integer, ? super Boolean, Unit> callback) {
        Intrinsics.checkNotNullParameter(callback, "callback");
        this.callback = callback;
        this.textSize = 16;
    }

    private final void initContentView(View contentView) {
        contentView.findViewById(R.id.iv_close_novel_read_setting).setOnClickListener(this);
        View findViewById = contentView.findViewById(R.id.tv_textsize_value);
        Intrinsics.checkNotNullExpressionValue(findViewById, "contentView.findViewById<TextView>(R.id.tv_textsize_value)");
        setTv_textsize_value((TextView) findViewById);
        if (Intrinsics.areEqual(C0885h.m210b(), "")) {
            getTv_textsize_value().setText("16");
        } else {
            getTv_textsize_value().setText(C0885h.m210b());
        }
        ((Switch) contentView.findViewById(R.id.sw_switch_model_dark)).setOnClickListener(this);
        contentView.findViewById(R.id.tv_textsize_small).setOnClickListener(this);
        contentView.findViewById(R.id.tv_textsize_big).setOnClickListener(this);
        View findViewById2 = contentView.findViewById(R.id.progress_brightness);
        Intrinsics.checkNotNullExpressionValue(findViewById2, "contentView.findViewById<SeekBar>(R.id.progress_brightness)");
        setProgress_brightness((SeekBar) findViewById2);
        View findViewById3 = contentView.findViewById(R.id.ra_group_background);
        Intrinsics.checkNotNullExpressionValue(findViewById3, "contentView.findViewById<RadioGroup>(R.id.ra_group_background)");
        setRa_group_background((RadioGroup) findViewById3);
        if (Intrinsics.areEqual(C0885h.m209a(), "")) {
            getRa_group_background().check(R.id.ra_novelcolor_one);
        } else if (Intrinsics.areEqual(C0885h.m209a(), "0")) {
            getRa_group_background().check(R.id.ra_novelcolor_one);
            this.colorBgPosition = 0;
        } else if (Intrinsics.areEqual(C0885h.m209a(), "1")) {
            getRa_group_background().check(R.id.ra_novelcolor_two);
            this.colorBgPosition = 1;
        } else if (Intrinsics.areEqual(C0885h.m209a(), "2")) {
            getRa_group_background().check(R.id.ra_novelcolor_three);
            this.colorBgPosition = 2;
        } else if (Intrinsics.areEqual(C0885h.m209a(), "3")) {
            getRa_group_background().check(R.id.ra_novelcolor_four);
            this.colorBgPosition = 3;
        } else if (Intrinsics.areEqual(C0885h.m209a(), HomeDataHelper.type_tag)) {
            getRa_group_background().check(R.id.ra_novelcolor_five);
            this.colorBgPosition = 4;
        }
        contentView.findViewById(R.id.iv_close_novel_read_setting).setOnClickListener(this);
        getRa_group_background().setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() { // from class: b.a.a.a.t.e.m
            @Override // android.widget.RadioGroup.OnCheckedChangeListener
            public final void onCheckedChanged(RadioGroup radioGroup, int i2) {
                NovelReadSettingDialog.m5777initContentView$lambda1(NovelReadSettingDialog.this, radioGroup, i2);
            }
        });
        getProgress_brightness().setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() { // from class: com.jbzd.media.movecartoons.ui.dialog.NovelReadSettingDialog$initContentView$2
            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onProgressChanged(@Nullable SeekBar seekBar, int progress, boolean fromUser) {
                NovelReadSettingDialog.this.setWindowBrightness(progress / 100.0f);
                Context context = NovelReadSettingDialog.this.getContext();
                Objects.requireNonNull(context, "null cannot be cast to non-null type android.app.Activity");
                Activity activity = (Activity) context;
                float windowBrightness = NovelReadSettingDialog.this.getWindowBrightness() * 255;
                Intrinsics.checkNotNullParameter(activity, "activity");
                WindowManager.LayoutParams attributes = activity.getWindow().getAttributes();
                float f2 = windowBrightness * 0.003921569f;
                attributes.screenBrightness = f2;
                Intrinsics.stringPlus("set  lp.screenBrightness == ", Float.valueOf(f2));
                activity.getWindow().setAttributes(attributes);
            }

            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onStartTrackingTouch(@Nullable SeekBar seekBar) {
            }

            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onStopTrackingTouch(@Nullable SeekBar seekBar) {
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initContentView$lambda-1, reason: not valid java name */
    public static final void m5777initContentView$lambda1(NovelReadSettingDialog this$0, RadioGroup radioGroup, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        switch (i2) {
            case R.id.ra_novelcolor_four /* 2131362993 */:
                this$0.getRa_group_background().check(R.id.ra_novelcolor_four);
                this$0.setColorBgPosition(3);
                break;
            case R.id.ra_novelcolor_one /* 2131362994 */:
                this$0.getRa_group_background().check(R.id.ra_novelcolor_one);
                this$0.setColorBgPosition(0);
                break;
            case R.id.ra_novelcolor_three /* 2131362995 */:
                this$0.getRa_group_background().check(R.id.ra_novelcolor_three);
                this$0.setColorBgPosition(2);
                break;
            case R.id.ra_novelcolor_two /* 2131362996 */:
                this$0.getRa_group_background().check(R.id.ra_novelcolor_two);
                this$0.setColorBgPosition(1);
                break;
            default:
                this$0.getRa_group_background().check(R.id.ra_novelcolor_five);
                this$0.setColorBgPosition(4);
                break;
        }
        String value = String.valueOf(this$0.getColorBgPosition());
        Intrinsics.checkNotNullParameter(value, "themePosition");
        Intrinsics.checkNotNullParameter("novel_theme_position", "key");
        Intrinsics.checkNotNullParameter(value, "value");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        SharedPreferences.Editor editor = sharedPreferences.edit();
        Intrinsics.checkExpressionValueIsNotNull(editor, "editor");
        editor.putString("novel_theme_position", value);
        editor.commit();
        this$0.callback.invoke(Float.valueOf(Float.parseFloat(this$0.getTv_textsize_value().getText().toString())), Float.valueOf(0.5f), Integer.valueOf(this$0.getColorBgPosition()), Boolean.valueOf(this$0.getReadDarkModel()));
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final Activity getActivity() {
        Activity activity = this.activity;
        if (activity != null) {
            return activity;
        }
        Intrinsics.throwUninitializedPropertyAccessException(ActivityChooserModel.ATTRIBUTE_ACTIVITY);
        throw null;
    }

    public final int getColorBgPosition() {
        return this.colorBgPosition;
    }

    @NotNull
    public final ImageView getIv_close_novel_read_setting() {
        ImageView imageView = this.iv_close_novel_read_setting;
        if (imageView != null) {
            return imageView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("iv_close_novel_read_setting");
        throw null;
    }

    @NotNull
    public final SeekBar getProgress_brightness() {
        SeekBar seekBar = this.progress_brightness;
        if (seekBar != null) {
            return seekBar;
        }
        Intrinsics.throwUninitializedPropertyAccessException("progress_brightness");
        throw null;
    }

    @NotNull
    public final RadioGroup getRa_group_background() {
        RadioGroup radioGroup = this.ra_group_background;
        if (radioGroup != null) {
            return radioGroup;
        }
        Intrinsics.throwUninitializedPropertyAccessException("ra_group_background");
        throw null;
    }

    public final boolean getReadDarkModel() {
        return this.readDarkModel;
    }

    @NotNull
    public final SeekBar getSeekpar_auto_page() {
        SeekBar seekBar = this.seekpar_auto_page;
        if (seekBar != null) {
            return seekBar;
        }
        Intrinsics.throwUninitializedPropertyAccessException("seekpar_auto_page");
        throw null;
    }

    public final int getShowProgress() {
        return this.showProgress;
    }

    public final int getTextSize() {
        return this.textSize;
    }

    @NotNull
    public final TextView getTv_textsize_value() {
        TextView textView = this.tv_textsize_value;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("tv_textsize_value");
        throw null;
    }

    public final float getWindowBrightness() {
        return this.windowBrightness;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        int id = view.getId();
        Float valueOf = Float.valueOf(0.5f);
        if (id == R.id.tv_textsize_small) {
            int parseInt = Integer.parseInt(getTv_textsize_value().getText().toString());
            this.textSize = parseInt;
            if (parseInt > 12) {
                getTv_textsize_value().setText(String.valueOf(this.textSize - 1));
            }
            this.callback.invoke(Float.valueOf(Float.parseFloat(getTv_textsize_value().getText().toString())), valueOf, Integer.valueOf(this.colorBgPosition), Boolean.valueOf(this.readDarkModel));
            return;
        }
        if (view.getId() == R.id.tv_textsize_big) {
            int parseInt2 = Integer.parseInt(getTv_textsize_value().getText().toString());
            this.textSize = parseInt2;
            if (parseInt2 < 20) {
                getTv_textsize_value().setText(String.valueOf(this.textSize + 1));
                this.callback.invoke(Float.valueOf(Float.parseFloat(getTv_textsize_value().getText().toString())), valueOf, Integer.valueOf(this.colorBgPosition), Boolean.valueOf(this.readDarkModel));
                return;
            }
            return;
        }
        if (view.getId() != R.id.iv_close_novel_read_setting) {
            if (view.getId() == R.id.sw_switch_model_dark) {
                this.readDarkModel = !this.readDarkModel;
                this.callback.invoke(Float.valueOf(Float.parseFloat(getTv_textsize_value().getText().toString())), valueOf, Integer.valueOf(this.colorBgPosition), Boolean.valueOf(this.readDarkModel));
                return;
            }
            return;
        }
        String value = getTv_textsize_value().getText().toString();
        Intrinsics.checkNotNullParameter(value, "textSize");
        Intrinsics.checkNotNullParameter("novel_text_size", "key");
        Intrinsics.checkNotNullParameter(value, "value");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        SharedPreferences.Editor editor = sharedPreferences.edit();
        Intrinsics.checkExpressionValueIsNotNull(editor, "editor");
        editor.putString("novel_text_size", value);
        editor.commit();
        dismissAllowingStateLoss();
    }

    @Override // androidx.fragment.app.DialogFragment, androidx.fragment.app.Fragment
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setStyle(0, R.style.dialog_center);
    }

    @Override // com.google.android.material.bottomsheet.BottomSheetDialogFragment, androidx.appcompat.app.AppCompatDialogFragment, androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        Dialog onCreateDialog = super.onCreateDialog(savedInstanceState);
        Intrinsics.checkNotNullExpressionValue(onCreateDialog, "super.onCreateDialog(savedInstanceState)");
        View contentView = LayoutInflater.from(getContext()).inflate(R.layout.dialog_novel_read_setting, (ViewGroup) null);
        onCreateDialog.setContentView(contentView);
        Intrinsics.checkNotNullExpressionValue(contentView, "contentView");
        initContentView(contentView);
        Window window = onCreateDialog.getWindow();
        WindowManager.LayoutParams attributes = window != null ? window.getAttributes() : null;
        if (attributes != null) {
            attributes.windowAnimations = R.style.BottomShowAnimation;
        }
        return onCreateDialog;
    }

    public final void setActivity(@NotNull Activity activity) {
        Intrinsics.checkNotNullParameter(activity, "<set-?>");
        this.activity = activity;
    }

    public final void setColorBgPosition(int i2) {
        this.colorBgPosition = i2;
    }

    public final void setIv_close_novel_read_setting(@NotNull ImageView imageView) {
        Intrinsics.checkNotNullParameter(imageView, "<set-?>");
        this.iv_close_novel_read_setting = imageView;
    }

    public final void setProgress_brightness(@NotNull SeekBar seekBar) {
        Intrinsics.checkNotNullParameter(seekBar, "<set-?>");
        this.progress_brightness = seekBar;
    }

    public final void setRa_group_background(@NotNull RadioGroup radioGroup) {
        Intrinsics.checkNotNullParameter(radioGroup, "<set-?>");
        this.ra_group_background = radioGroup;
    }

    public final void setReadDarkModel(boolean z) {
        this.readDarkModel = z;
    }

    public final void setSeekpar_auto_page(@NotNull SeekBar seekBar) {
        Intrinsics.checkNotNullParameter(seekBar, "<set-?>");
        this.seekpar_auto_page = seekBar;
    }

    public final void setShowProgress(int i2) {
        this.showProgress = i2;
    }

    public final void setTextSize(int i2) {
        this.textSize = i2;
    }

    public final void setTv_textsize_value(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.tv_textsize_value = textView;
    }

    public final void setWindowBrightness(float f2) {
        this.windowBrightness = f2;
    }
}
