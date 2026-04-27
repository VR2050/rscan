package im.uwrkaxlmjj.ui.settings;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.text.TextPaint;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.DownloadController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.hviews.MrySwitch;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class AutoDownloadSettingActivity extends BaseFragment {
    private boolean animateChecked;
    private int autoDownloadRow;
    private int autoDownloadSectionRow;
    private int currentPresetNum;
    private int currentType;
    private DownloadController.Preset defaultPreset;
    private int filesRow;
    FrameLayout frameLayout;
    private String key;
    private String key2;
    private LinearLayoutManager layoutManager;
    private int photosRow;
    private int rowCount;
    private int typeHeaderRow;
    private DownloadController.Preset typePreset;
    private int typeSectionRow;
    private int usageHeaderRow;
    private int usageProgressRow;
    private int usageSectionRow;
    private int videosRow;
    private boolean wereAnyChanges;
    private ArrayList<DownloadController.Preset> presets = new ArrayList<>();
    private int selectedPreset = 1;
    private View.OnClickListener clickListener = new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.AutoDownloadSettingActivity.3
        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            final int type;
            DownloadController.Preset currentPreset;
            final String key;
            final String key2;
            if (!view.isEnabled()) {
                return;
            }
            if (view.getId() == R.attr.rl_photo) {
                type = 1;
            } else {
                int type2 = view.getId();
                if (type2 == R.attr.rl_video) {
                    type = 4;
                } else {
                    type = 8;
                }
            }
            final int index = DownloadController.typeToIndex(type);
            if (AutoDownloadSettingActivity.this.currentType == 0) {
                DownloadController.Preset currentPreset2 = DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).getCurrentMobilePreset();
                currentPreset = currentPreset2;
                key = "mobilePreset";
                key2 = "currentMobilePreset";
            } else if (AutoDownloadSettingActivity.this.currentType == 1) {
                DownloadController.Preset currentPreset3 = DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).getCurrentWiFiPreset();
                currentPreset = currentPreset3;
                key = "wifiPreset";
                key2 = "currentWifiPreset";
            } else {
                DownloadController.Preset currentPreset4 = DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).getCurrentRoamingPreset();
                currentPreset = currentPreset4;
                key = "roamingPreset";
                key2 = "currentRoamingPreset";
            }
            if (AutoDownloadSettingActivity.this.getParentActivity() == null) {
                return;
            }
            List<Boolean> arrListChecked = new ArrayList<>();
            for (int a = 0; a < 4; a++) {
                if (a == 0) {
                    arrListChecked.add(Boolean.valueOf((currentPreset.mask[0] & type) != 0));
                } else if (a == 1) {
                    arrListChecked.add(Boolean.valueOf((currentPreset.mask[1] & type) != 0));
                } else if (a == 2) {
                    arrListChecked.add(Boolean.valueOf((currentPreset.mask[2] & type) != 0));
                } else if (a == 3) {
                    arrListChecked.add(Boolean.valueOf((currentPreset.mask[3] & type) != 0));
                }
            }
            if (type == 1) {
                View divider = new View(AutoDownloadSettingActivity.this.getParentActivity());
                divider.setBackgroundColor(Theme.getColor(Theme.key_divider));
            }
            if (type == 1) {
                AutoDownloadSettingActivity.this.presentFragment(new PhotoAutoDownloadSettingActivity(arrListChecked, new activityButtonClickListener() { // from class: im.uwrkaxlmjj.ui.settings.AutoDownloadSettingActivity.3.1
                    @Override // im.uwrkaxlmjj.ui.settings.AutoDownloadSettingActivity.activityButtonClickListener
                    public void onSaveBtnClick(List<Boolean> arrList, long size, boolean checked) {
                        if (AutoDownloadSettingActivity.this.currentPresetNum != 3) {
                            if (AutoDownloadSettingActivity.this.currentPresetNum == 0) {
                                AutoDownloadSettingActivity.this.typePreset.set(AutoDownloadSettingActivity.this.lowPreset);
                            } else if (AutoDownloadSettingActivity.this.currentPresetNum == 1) {
                                AutoDownloadSettingActivity.this.typePreset.set(AutoDownloadSettingActivity.this.mediumPreset);
                            } else if (AutoDownloadSettingActivity.this.currentPresetNum == 2) {
                                AutoDownloadSettingActivity.this.typePreset.set(AutoDownloadSettingActivity.this.highPreset);
                            }
                        }
                        for (int a2 = 0; a2 < 4; a2++) {
                            if (arrList.get(a2).booleanValue()) {
                                int[] iArr = AutoDownloadSettingActivity.this.typePreset.mask;
                                iArr[a2] = iArr[a2] | type;
                            } else {
                                int[] iArr2 = AutoDownloadSettingActivity.this.typePreset.mask;
                                iArr2[a2] = iArr2[a2] & (~type);
                            }
                        }
                        SharedPreferences.Editor editor = MessagesController.getMainSettings(AutoDownloadSettingActivity.this.currentAccount).edit();
                        editor.putString(key, AutoDownloadSettingActivity.this.typePreset.toString());
                        editor.putInt(key2, AutoDownloadSettingActivity.this.currentPresetNum = 3);
                        if (AutoDownloadSettingActivity.this.currentType == 0) {
                            DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentMobilePreset = AutoDownloadSettingActivity.this.currentPresetNum;
                        } else if (AutoDownloadSettingActivity.this.currentType == 1) {
                            DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentWifiPreset = AutoDownloadSettingActivity.this.currentPresetNum;
                        } else {
                            DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentRoamingPreset = AutoDownloadSettingActivity.this.currentPresetNum;
                        }
                        editor.commit();
                        AutoDownloadSettingActivity.this.initState();
                        DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).checkAutodownloadSettings();
                        AutoDownloadSettingActivity.this.wereAnyChanges = true;
                        AutoDownloadSettingActivity.this.fillPresets();
                    }
                }));
                return;
            }
            if (type == 4) {
                final int i = type;
                final String str = key;
                final String str2 = key2;
                AutoDownloadSettingActivity.this.presentFragment(new VideoAutoDownloadSettingActivity(arrListChecked, currentPreset.sizes[index], currentPreset.preloadVideo, new activityButtonClickListener() { // from class: im.uwrkaxlmjj.ui.settings.AutoDownloadSettingActivity.3.2
                    @Override // im.uwrkaxlmjj.ui.settings.AutoDownloadSettingActivity.activityButtonClickListener
                    public void onSaveBtnClick(List<Boolean> arrList, long size, boolean checked) {
                        if (AutoDownloadSettingActivity.this.currentPresetNum != 3) {
                            if (AutoDownloadSettingActivity.this.currentPresetNum == 0) {
                                AutoDownloadSettingActivity.this.typePreset.set(AutoDownloadSettingActivity.this.lowPreset);
                            } else if (AutoDownloadSettingActivity.this.currentPresetNum == 1) {
                                AutoDownloadSettingActivity.this.typePreset.set(AutoDownloadSettingActivity.this.mediumPreset);
                            } else if (AutoDownloadSettingActivity.this.currentPresetNum == 2) {
                                AutoDownloadSettingActivity.this.typePreset.set(AutoDownloadSettingActivity.this.highPreset);
                            }
                        }
                        for (int a2 = 0; a2 < 4; a2++) {
                            if (arrList.get(a2).booleanValue()) {
                                int[] iArr = AutoDownloadSettingActivity.this.typePreset.mask;
                                iArr[a2] = iArr[a2] | i;
                            } else {
                                int[] iArr2 = AutoDownloadSettingActivity.this.typePreset.mask;
                                iArr2[a2] = iArr2[a2] & (~i);
                            }
                        }
                        AutoDownloadSettingActivity.this.typePreset.sizes[index] = (int) size;
                        AutoDownloadSettingActivity.this.typePreset.preloadVideo = checked;
                        SharedPreferences.Editor editor = MessagesController.getMainSettings(AutoDownloadSettingActivity.this.currentAccount).edit();
                        editor.putString(str, AutoDownloadSettingActivity.this.typePreset.toString());
                        editor.putInt(str2, AutoDownloadSettingActivity.this.currentPresetNum = 3);
                        if (AutoDownloadSettingActivity.this.currentType == 0) {
                            DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentMobilePreset = AutoDownloadSettingActivity.this.currentPresetNum;
                        } else if (AutoDownloadSettingActivity.this.currentType == 1) {
                            DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentWifiPreset = AutoDownloadSettingActivity.this.currentPresetNum;
                        } else {
                            DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentRoamingPreset = AutoDownloadSettingActivity.this.currentPresetNum;
                        }
                        editor.commit();
                        AutoDownloadSettingActivity.this.initState();
                        DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).checkAutodownloadSettings();
                        AutoDownloadSettingActivity.this.wereAnyChanges = true;
                        AutoDownloadSettingActivity.this.fillPresets();
                    }
                }));
                return;
            }
            final int i2 = type;
            final String str3 = key;
            final String str4 = key2;
            AutoDownloadSettingActivity.this.presentFragment(new FileAutoDownloadSettingActivity(arrListChecked, currentPreset.sizes[index], new activityButtonClickListener() { // from class: im.uwrkaxlmjj.ui.settings.AutoDownloadSettingActivity.3.3
                @Override // im.uwrkaxlmjj.ui.settings.AutoDownloadSettingActivity.activityButtonClickListener
                public void onSaveBtnClick(List<Boolean> arrList, long size, boolean checked) {
                    if (AutoDownloadSettingActivity.this.currentPresetNum != 3) {
                        if (AutoDownloadSettingActivity.this.currentPresetNum == 0) {
                            AutoDownloadSettingActivity.this.typePreset.set(AutoDownloadSettingActivity.this.lowPreset);
                        } else if (AutoDownloadSettingActivity.this.currentPresetNum == 1) {
                            AutoDownloadSettingActivity.this.typePreset.set(AutoDownloadSettingActivity.this.mediumPreset);
                        } else if (AutoDownloadSettingActivity.this.currentPresetNum == 2) {
                            AutoDownloadSettingActivity.this.typePreset.set(AutoDownloadSettingActivity.this.highPreset);
                        }
                    }
                    for (int a2 = 0; a2 < 4; a2++) {
                        if (arrList.get(a2).booleanValue()) {
                            int[] iArr = AutoDownloadSettingActivity.this.typePreset.mask;
                            iArr[a2] = iArr[a2] | i2;
                        } else {
                            int[] iArr2 = AutoDownloadSettingActivity.this.typePreset.mask;
                            iArr2[a2] = iArr2[a2] & (~i2);
                        }
                    }
                    AutoDownloadSettingActivity.this.typePreset.sizes[index] = (int) size;
                    SharedPreferences.Editor editor = MessagesController.getMainSettings(AutoDownloadSettingActivity.this.currentAccount).edit();
                    editor.putString(str3, AutoDownloadSettingActivity.this.typePreset.toString());
                    editor.putInt(str4, AutoDownloadSettingActivity.this.currentPresetNum = 3);
                    if (AutoDownloadSettingActivity.this.currentType == 0) {
                        DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentMobilePreset = AutoDownloadSettingActivity.this.currentPresetNum;
                    } else if (AutoDownloadSettingActivity.this.currentType == 1) {
                        DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentWifiPreset = AutoDownloadSettingActivity.this.currentPresetNum;
                    } else {
                        DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentRoamingPreset = AutoDownloadSettingActivity.this.currentPresetNum;
                    }
                    editor.commit();
                    AutoDownloadSettingActivity.this.initState();
                    DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).checkAutodownloadSettings();
                    AutoDownloadSettingActivity.this.wereAnyChanges = true;
                    AutoDownloadSettingActivity.this.fillPresets();
                }
            }));
        }
    };
    private DownloadController.Preset lowPreset = DownloadController.getInstance(this.currentAccount).lowPreset;
    private DownloadController.Preset mediumPreset = DownloadController.getInstance(this.currentAccount).mediumPreset;
    private DownloadController.Preset highPreset = DownloadController.getInstance(this.currentAccount).highPreset;

    public interface activityButtonClickListener {
        void onSaveBtnClick(List<Boolean> list, long j, boolean z);
    }

    private class PresetChooseView extends View {
        private int circleSize;
        private String custom;
        private int customSize;
        private int gapSize;
        private String high;
        private int highSize;
        private int lineSize;
        private String low;
        private int lowSize;
        private String medium;
        private int mediumSize;
        private boolean moving;
        private Paint paint;
        private int sideSide;
        private boolean startMoving;
        private int startMovingPreset;
        private float startX;
        private TextPaint textPaint;

        public PresetChooseView(Context context) {
            super(context);
            this.paint = new Paint(1);
            TextPaint textPaint = new TextPaint(1);
            this.textPaint = textPaint;
            textPaint.setTextSize(AndroidUtilities.dp(13.0f));
            this.low = LocaleController.getString("AutoDownloadLow", R.string.AutoDownloadLow);
            this.lowSize = (int) Math.ceil(this.textPaint.measureText(r3));
            this.medium = LocaleController.getString("AutoDownloadMedium", R.string.AutoDownloadMedium);
            this.mediumSize = (int) Math.ceil(this.textPaint.measureText(r3));
            this.high = LocaleController.getString("AutoDownloadHigh", R.string.AutoDownloadHigh);
            this.highSize = (int) Math.ceil(this.textPaint.measureText(r3));
            this.custom = LocaleController.getString("AutoDownloadCustom", R.string.AutoDownloadCustom);
            this.customSize = (int) Math.ceil(this.textPaint.measureText(r3));
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            float x = event.getX();
            if (event.getAction() == 0) {
                getParent().requestDisallowInterceptTouchEvent(true);
                int a = 0;
                while (true) {
                    if (a >= AutoDownloadSettingActivity.this.presets.size()) {
                        break;
                    }
                    int i = this.sideSide;
                    int i2 = this.lineSize + (this.gapSize * 2);
                    int i3 = this.circleSize;
                    int cx = i + ((i2 + i3) * a) + (i3 / 2);
                    if (x > cx - AndroidUtilities.dp(15.0f) && x < AndroidUtilities.dp(15.0f) + cx) {
                        this.startMoving = a == AutoDownloadSettingActivity.this.selectedPreset;
                        this.startX = x;
                        this.startMovingPreset = AutoDownloadSettingActivity.this.selectedPreset;
                    } else {
                        a++;
                    }
                }
            } else if (event.getAction() == 2) {
                if (this.startMoving) {
                    if (Math.abs(this.startX - x) >= AndroidUtilities.getPixelsInCM(0.5f, true)) {
                        this.moving = true;
                        this.startMoving = false;
                    }
                } else if (this.moving) {
                    int a2 = 0;
                    while (true) {
                        if (a2 >= AutoDownloadSettingActivity.this.presets.size()) {
                            break;
                        }
                        int i4 = this.sideSide;
                        int i5 = this.lineSize;
                        int i6 = this.gapSize;
                        int i7 = this.circleSize;
                        int cx2 = i4 + (((i6 * 2) + i5 + i7) * a2) + (i7 / 2);
                        int diff = (i5 / 2) + (i7 / 2) + i6;
                        if (x > cx2 - diff && x < cx2 + diff) {
                            if (AutoDownloadSettingActivity.this.selectedPreset != a2) {
                                setPreset(a2);
                            }
                        } else {
                            a2++;
                        }
                    }
                }
            } else if (event.getAction() == 1 || event.getAction() == 3) {
                if (this.moving) {
                    if (AutoDownloadSettingActivity.this.selectedPreset != this.startMovingPreset) {
                        setPreset(AutoDownloadSettingActivity.this.selectedPreset);
                    }
                } else {
                    int a3 = 0;
                    while (true) {
                        if (a3 >= 5) {
                            break;
                        }
                        int i8 = this.sideSide;
                        int i9 = this.lineSize + (this.gapSize * 2);
                        int i10 = this.circleSize;
                        int cx3 = i8 + ((i9 + i10) * a3) + (i10 / 2);
                        if (x > cx3 - AndroidUtilities.dp(15.0f) && x < AndroidUtilities.dp(15.0f) + cx3) {
                            if (AutoDownloadSettingActivity.this.selectedPreset != a3) {
                                setPreset(a3);
                            }
                        } else {
                            a3++;
                        }
                    }
                }
                this.startMoving = false;
                this.moving = false;
            }
            return true;
        }

        private void setPreset(int index) {
            AutoDownloadSettingActivity.this.selectedPreset = index;
            DownloadController.Preset preset = (DownloadController.Preset) AutoDownloadSettingActivity.this.presets.get(AutoDownloadSettingActivity.this.selectedPreset);
            if (preset == AutoDownloadSettingActivity.this.lowPreset) {
                AutoDownloadSettingActivity.this.currentPresetNum = 0;
            } else if (preset == AutoDownloadSettingActivity.this.mediumPreset) {
                AutoDownloadSettingActivity.this.currentPresetNum = 1;
            } else if (preset == AutoDownloadSettingActivity.this.highPreset) {
                AutoDownloadSettingActivity.this.currentPresetNum = 2;
            } else {
                AutoDownloadSettingActivity.this.currentPresetNum = 3;
            }
            if (AutoDownloadSettingActivity.this.currentType == 0) {
                DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentMobilePreset = AutoDownloadSettingActivity.this.currentPresetNum;
            } else if (AutoDownloadSettingActivity.this.currentType == 1) {
                DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentWifiPreset = AutoDownloadSettingActivity.this.currentPresetNum;
            } else {
                DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentRoamingPreset = AutoDownloadSettingActivity.this.currentPresetNum;
            }
            SharedPreferences.Editor editor = MessagesController.getMainSettings(AutoDownloadSettingActivity.this.currentAccount).edit();
            editor.putInt(AutoDownloadSettingActivity.this.key2, AutoDownloadSettingActivity.this.currentPresetNum);
            editor.commit();
            DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).checkAutodownloadSettings();
            AutoDownloadSettingActivity.this.initState();
            AutoDownloadSettingActivity.this.wereAnyChanges = true;
            invalidate();
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(74.0f), 1073741824));
            View.MeasureSpec.getSize(widthMeasureSpec);
            this.circleSize = AndroidUtilities.dp(6.0f);
            this.gapSize = AndroidUtilities.dp(2.0f);
            this.sideSide = AndroidUtilities.dp(22.0f);
            this.lineSize = (((getMeasuredWidth() - (this.circleSize * AutoDownloadSettingActivity.this.presets.size())) - ((this.gapSize * 2) * (AutoDownloadSettingActivity.this.presets.size() - 1))) - (this.sideSide * 2)) / (AutoDownloadSettingActivity.this.presets.size() - 1);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            String text;
            int size;
            this.textPaint.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
            int cy = (getMeasuredHeight() / 2) + AndroidUtilities.dp(11.0f);
            int a = 0;
            while (a < AutoDownloadSettingActivity.this.presets.size()) {
                int i = this.sideSide;
                int i2 = this.lineSize + (this.gapSize * 2);
                int i3 = this.circleSize;
                int cx = i + ((i2 + i3) * a) + (i3 / 2);
                if (a <= AutoDownloadSettingActivity.this.selectedPreset) {
                    this.paint.setColor(Theme.getColor(Theme.key_switchTrackChecked));
                } else {
                    this.paint.setColor(Theme.getColor(Theme.key_switchTrack));
                }
                canvas.drawCircle(cx, cy, a == AutoDownloadSettingActivity.this.selectedPreset ? AndroidUtilities.dp(6.0f) : this.circleSize / 2, this.paint);
                if (a != 0) {
                    int x = ((cx - (this.circleSize / 2)) - this.gapSize) - this.lineSize;
                    int width = this.lineSize;
                    if (a == AutoDownloadSettingActivity.this.selectedPreset || a == AutoDownloadSettingActivity.this.selectedPreset + 1) {
                        width -= AndroidUtilities.dp(3.0f);
                    }
                    if (a == AutoDownloadSettingActivity.this.selectedPreset + 1) {
                        x += AndroidUtilities.dp(3.0f);
                    }
                    canvas.drawRect(x, cy - AndroidUtilities.dp(1.0f), x + width, AndroidUtilities.dp(1.0f) + cy, this.paint);
                }
                DownloadController.Preset preset = (DownloadController.Preset) AutoDownloadSettingActivity.this.presets.get(a);
                if (preset != AutoDownloadSettingActivity.this.lowPreset) {
                    if (preset != AutoDownloadSettingActivity.this.mediumPreset) {
                        if (preset == AutoDownloadSettingActivity.this.highPreset) {
                            text = this.high;
                            size = this.highSize;
                        } else {
                            text = this.custom;
                            size = this.customSize;
                        }
                    } else {
                        text = this.medium;
                        size = this.mediumSize;
                    }
                } else {
                    text = this.low;
                    size = this.lowSize;
                }
                if (a != 0) {
                    if (a == AutoDownloadSettingActivity.this.presets.size() - 1) {
                        canvas.drawText(text, (getMeasuredWidth() - size) - AndroidUtilities.dp(22.0f), AndroidUtilities.dp(28.0f), this.textPaint);
                    } else {
                        canvas.drawText(text, cx - (size / 2), AndroidUtilities.dp(28.0f), this.textPaint);
                    }
                } else {
                    canvas.drawText(text, AndroidUtilities.dp(22.0f), AndroidUtilities.dp(28.0f), this.textPaint);
                }
                a++;
            }
        }
    }

    public AutoDownloadSettingActivity(int type) {
        this.currentType = type;
        int i = this.currentType;
        if (i == 0) {
            this.currentPresetNum = DownloadController.getInstance(this.currentAccount).currentMobilePreset;
            this.typePreset = DownloadController.getInstance(this.currentAccount).mobilePreset;
            this.defaultPreset = this.mediumPreset;
            this.key = "mobilePreset";
            this.key2 = "currentMobilePreset";
            return;
        }
        if (i == 1) {
            this.currentPresetNum = DownloadController.getInstance(this.currentAccount).currentWifiPreset;
            this.typePreset = DownloadController.getInstance(this.currentAccount).wifiPreset;
            this.defaultPreset = this.highPreset;
            this.key = "wifiPreset";
            this.key2 = "currentWifiPreset";
            return;
        }
        this.currentPresetNum = DownloadController.getInstance(this.currentAccount).currentRoamingPreset;
        this.typePreset = DownloadController.getInstance(this.currentAccount).roamingPreset;
        this.defaultPreset = this.lowPreset;
        this.key = "roamingPreset";
        this.key2 = "currentRoamingPreset";
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        fillPresets();
        updateRows();
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        int i = this.currentType;
        if (i == 0) {
            this.actionBar.setTitle(LocaleController.getString("AutoDownloadOnMobileData", R.string.AutoDownloadOnMobileData));
        } else if (i == 1) {
            this.actionBar.setTitle(LocaleController.getString("AutoDownloadOnWiFiData", R.string.AutoDownloadOnWiFiData));
        } else if (i == 2) {
            this.actionBar.setTitle(LocaleController.getString("AutoDownloadOnRoamingData", R.string.AutoDownloadOnRoamingData));
        }
        if (AndroidUtilities.isTablet()) {
            this.actionBar.setOccupyStatusBar(false);
        }
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.settings.AutoDownloadSettingActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    AutoDownloadSettingActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_setting_auto_download, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.frameLayout = (FrameLayout) this.fragmentView.findViewById(R.attr.fl_container);
        PresetChooseView view1 = new PresetChooseView(context);
        view1.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.frameLayout.addView(view1, LayoutHelper.createFrame(-1, -1, 51));
        initView(context);
        initListener();
        return this.fragmentView;
    }

    private void initView(Context context) {
        this.fragmentView.findViewById(R.attr.rl_auto_download).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_photo).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0, 0, Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_video).setBackground(Theme.getSelectorDrawable(true));
        this.fragmentView.findViewById(R.attr.rl_file).setBackground(Theme.getRoundRectSelectorDrawable(0, 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    private void initListener() {
        this.fragmentView.findViewById(R.attr.rl_auto_download).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.AutoDownloadSettingActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (AutoDownloadSettingActivity.this.currentPresetNum != 3) {
                    if (AutoDownloadSettingActivity.this.currentPresetNum == 0) {
                        AutoDownloadSettingActivity.this.typePreset.set(AutoDownloadSettingActivity.this.lowPreset);
                    } else if (AutoDownloadSettingActivity.this.currentPresetNum == 1) {
                        AutoDownloadSettingActivity.this.typePreset.set(AutoDownloadSettingActivity.this.mediumPreset);
                    } else if (AutoDownloadSettingActivity.this.currentPresetNum == 2) {
                        AutoDownloadSettingActivity.this.typePreset.set(AutoDownloadSettingActivity.this.highPreset);
                    }
                }
                ((MrySwitch) AutoDownloadSettingActivity.this.fragmentView.findViewById(R.attr.switch_auto_download)).setChecked(AutoDownloadSettingActivity.this.typePreset.enabled, true);
                boolean checked = ((MrySwitch) AutoDownloadSettingActivity.this.fragmentView.findViewById(R.attr.switch_auto_download)).isChecked();
                if (checked || !AutoDownloadSettingActivity.this.typePreset.enabled) {
                    AutoDownloadSettingActivity.this.typePreset.enabled = !AutoDownloadSettingActivity.this.typePreset.enabled;
                } else {
                    System.arraycopy(AutoDownloadSettingActivity.this.defaultPreset.mask, 0, AutoDownloadSettingActivity.this.typePreset.mask, 0, 4);
                }
                view.setTag(AutoDownloadSettingActivity.this.typePreset.enabled ? Theme.key_windowBackgroundChecked : Theme.key_windowBackgroundUnchecked);
                AutoDownloadSettingActivity.this.updateRows();
                if (!AutoDownloadSettingActivity.this.typePreset.enabled) {
                    AutoDownloadSettingActivity.this.fragmentView.findViewById(R.attr.ll_sub).setVisibility(8);
                } else {
                    AutoDownloadSettingActivity.this.fragmentView.findViewById(R.attr.ll_sub).setVisibility(0);
                }
                SharedPreferences.Editor editor = MessagesController.getMainSettings(AutoDownloadSettingActivity.this.currentAccount).edit();
                editor.putString(AutoDownloadSettingActivity.this.key, AutoDownloadSettingActivity.this.typePreset.toString());
                editor.putInt(AutoDownloadSettingActivity.this.key2, AutoDownloadSettingActivity.this.currentPresetNum = 3);
                if (AutoDownloadSettingActivity.this.currentType == 0) {
                    DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentMobilePreset = AutoDownloadSettingActivity.this.currentPresetNum;
                } else if (AutoDownloadSettingActivity.this.currentType == 1) {
                    DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentWifiPreset = AutoDownloadSettingActivity.this.currentPresetNum;
                } else {
                    DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).currentRoamingPreset = AutoDownloadSettingActivity.this.currentPresetNum;
                }
                editor.commit();
                ((MrySwitch) AutoDownloadSettingActivity.this.fragmentView.findViewById(R.attr.switch_auto_download)).setChecked(!checked, true);
                DownloadController.getInstance(AutoDownloadSettingActivity.this.currentAccount).checkAutodownloadSettings();
                AutoDownloadSettingActivity.this.wereAnyChanges = true;
            }
        });
        this.fragmentView.findViewById(R.attr.rl_photo).setOnClickListener(this.clickListener);
        this.fragmentView.findViewById(R.attr.rl_video).setOnClickListener(this.clickListener);
        this.fragmentView.findViewById(R.attr.rl_file).setOnClickListener(this.clickListener);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        super.onActivityResultFragment(requestCode, resultCode, data);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        initState();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void initState() {
        ((MrySwitch) this.fragmentView.findViewById(R.attr.switch_auto_download)).setChecked(this.typePreset.enabled, true);
        if (!((MrySwitch) this.fragmentView.findViewById(R.attr.switch_auto_download)).isChecked()) {
            this.fragmentView.findViewById(R.attr.ll_sub).setVisibility(8);
        }
        initMediaDownloadState(1);
        initMediaDownloadState(4);
        initMediaDownloadState(8);
    }

    private void initMediaDownloadState(int iType) {
        DownloadController.Preset preset;
        int i = this.currentType;
        if (i == 0) {
            preset = DownloadController.getInstance(this.currentAccount).getCurrentMobilePreset();
        } else if (i == 1) {
            preset = DownloadController.getInstance(this.currentAccount).getCurrentWiFiPreset();
        } else {
            preset = DownloadController.getInstance(this.currentAccount).getCurrentRoamingPreset();
        }
        int maxSize = preset.sizes[DownloadController.typeToIndex(iType)];
        int count = 0;
        StringBuilder builder = new StringBuilder();
        for (int a = 0; a < preset.mask.length; a++) {
            if ((preset.mask[a] & iType) != 0) {
                if (builder.length() != 0) {
                    builder.append(", ");
                }
                if (a == 0) {
                    builder.append(LocaleController.getString("AutoDownloadContacts", R.string.AutoDownloadContacts));
                } else if (a == 1) {
                    builder.append(LocaleController.getString("AutoDownloadPm", R.string.AutoDownloadPm));
                } else if (a == 2) {
                    builder.append(LocaleController.getString("AutoDownloadGroups", R.string.AutoDownloadGroups));
                } else if (a == 3) {
                    builder.append(LocaleController.getString("AutoDownloadChannels", R.string.AutoDownloadChannels));
                }
                count++;
            }
        }
        if (count == 4) {
            builder.setLength(0);
            if (iType == 1) {
                builder.append(LocaleController.getString("AutoDownloadOnAllChats", R.string.AutoDownloadOnAllChats));
            } else {
                builder.append(LocaleController.formatString("AutoDownloadUpToOnAllChats", R.string.AutoDownloadUpToOnAllChats, AndroidUtilities.formatFileSize(maxSize)));
            }
        } else if (count == 0) {
            builder.append(LocaleController.getString("AutoDownloadOff", R.string.AutoDownloadOff));
        } else {
            builder = iType == 1 ? new StringBuilder(LocaleController.formatString("AutoDownloadOnFor", R.string.AutoDownloadOnFor, builder.toString())) : new StringBuilder(LocaleController.formatString("AutoDownloadOnUpToFor", R.string.AutoDownloadOnUpToFor, AndroidUtilities.formatFileSize(maxSize), builder.toString()));
        }
        if (iType == 1) {
            ((TextView) this.fragmentView.findViewById(R.attr.tv_photo)).setText(builder);
        } else if (iType == 4) {
            ((TextView) this.fragmentView.findViewById(R.attr.tv_video)).setText(builder);
        } else {
            ((TextView) this.fragmentView.findViewById(R.attr.tv_file)).setText(builder);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        if (this.wereAnyChanges) {
            DownloadController.getInstance(this.currentAccount).savePresetToServer(this.currentType);
            this.wereAnyChanges = false;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void fillPresets() {
        this.presets.clear();
        this.presets.add(this.lowPreset);
        this.presets.add(this.mediumPreset);
        this.presets.add(this.highPreset);
        if (!this.typePreset.equals(this.lowPreset) && !this.typePreset.equals(this.mediumPreset) && !this.typePreset.equals(this.highPreset)) {
            this.presets.add(this.typePreset);
        }
        Collections.sort(this.presets, new Comparator() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$AutoDownloadSettingActivity$PQSKihVBQQDxz3eARfOQpXMHpt8
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return AutoDownloadSettingActivity.lambda$fillPresets$0((DownloadController.Preset) obj, (DownloadController.Preset) obj2);
            }
        });
        int i = this.currentPresetNum;
        if (i == 0 || (i == 3 && this.typePreset.equals(this.lowPreset))) {
            this.selectedPreset = this.presets.indexOf(this.lowPreset);
            return;
        }
        int i2 = this.currentPresetNum;
        if (i2 == 1 || (i2 == 3 && this.typePreset.equals(this.mediumPreset))) {
            this.selectedPreset = this.presets.indexOf(this.mediumPreset);
            return;
        }
        int i3 = this.currentPresetNum;
        if (i3 == 2 || (i3 == 3 && this.typePreset.equals(this.highPreset))) {
            this.selectedPreset = this.presets.indexOf(this.highPreset);
        } else {
            this.selectedPreset = this.presets.indexOf(this.typePreset);
        }
    }

    static /* synthetic */ int lambda$fillPresets$0(DownloadController.Preset o1, DownloadController.Preset o2) {
        int index1 = DownloadController.typeToIndex(4);
        int index2 = DownloadController.typeToIndex(8);
        boolean video1 = false;
        boolean doc1 = false;
        for (int a = 0; a < o1.mask.length; a++) {
            if ((o1.mask[a] & 4) != 0) {
                video1 = true;
            }
            if ((o1.mask[a] & 8) != 0) {
                doc1 = true;
            }
            if (video1 && doc1) {
                break;
            }
        }
        int a2 = 0;
        boolean doc2 = false;
        for (int a3 = 0; a3 < o2.mask.length; a3++) {
            if ((o2.mask[a3] & 4) != 0) {
                a2 = 1;
            }
            if ((o2.mask[a3] & 8) != 0) {
                doc2 = true;
            }
            if (a2 != 0 && doc2) {
                break;
            }
        }
        int size1 = (video1 ? o1.sizes[index1] : 0) + (doc1 ? o1.sizes[index2] : 0);
        int size2 = (a2 != 0 ? o2.sizes[index1] : 0) + (doc2 ? o2.sizes[index2] : 0);
        if (size1 > size2) {
            return 1;
        }
        if (size1 >= size2) {
            return 0;
        }
        return -1;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateRows() {
        this.rowCount = 0;
        int i = 0 + 1;
        this.rowCount = i;
        this.autoDownloadRow = 0;
        this.rowCount = i + 1;
        this.autoDownloadSectionRow = i;
        if (this.typePreset.enabled) {
            int i2 = this.rowCount;
            int i3 = i2 + 1;
            this.rowCount = i3;
            this.usageHeaderRow = i2;
            int i4 = i3 + 1;
            this.rowCount = i4;
            this.usageProgressRow = i3;
            int i5 = i4 + 1;
            this.rowCount = i5;
            this.usageSectionRow = i4;
            int i6 = i5 + 1;
            this.rowCount = i6;
            this.typeHeaderRow = i5;
            int i7 = i6 + 1;
            this.rowCount = i7;
            this.photosRow = i6;
            int i8 = i7 + 1;
            this.rowCount = i8;
            this.videosRow = i7;
            int i9 = i8 + 1;
            this.rowCount = i9;
            this.filesRow = i8;
            this.rowCount = i9 + 1;
            this.typeSectionRow = i9;
            return;
        }
        this.usageHeaderRow = -1;
        this.usageProgressRow = -1;
        this.usageSectionRow = -1;
        this.typeHeaderRow = -1;
        this.photosRow = -1;
        this.videosRow = -1;
        this.filesRow = -1;
        this.typeSectionRow = -1;
    }
}
