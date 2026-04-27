package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.text.TextPaint;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.DefaultItemAnimator;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.DownloadController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.MaxFileSizeCell;
import im.uwrkaxlmjj.ui.cells.NotificationsCheckCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextCheckBoxCell;
import im.uwrkaxlmjj.ui.cells.TextCheckCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.components.CombinedDrawable;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
@Deprecated
public class DataAutoDownloadActivity extends BaseFragment {
    private boolean animateChecked;
    private int autoDownloadRow;
    private int autoDownloadSectionRow;
    private int currentPresetNum;
    private int currentType;
    private DownloadController.Preset defaultPreset;
    private int filesRow;
    private String key;
    private String key2;
    private LinearLayoutManager layoutManager;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
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
    private DownloadController.Preset lowPreset = DownloadController.getInstance(this.currentAccount).lowPreset;
    private DownloadController.Preset mediumPreset = DownloadController.getInstance(this.currentAccount).mediumPreset;
    private DownloadController.Preset highPreset = DownloadController.getInstance(this.currentAccount).highPreset;

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
                    if (a >= DataAutoDownloadActivity.this.presets.size()) {
                        break;
                    }
                    int i = this.sideSide;
                    int i2 = this.lineSize + (this.gapSize * 2);
                    int i3 = this.circleSize;
                    int cx = i + ((i2 + i3) * a) + (i3 / 2);
                    if (x > cx - AndroidUtilities.dp(15.0f) && x < AndroidUtilities.dp(15.0f) + cx) {
                        this.startMoving = a == DataAutoDownloadActivity.this.selectedPreset;
                        this.startX = x;
                        this.startMovingPreset = DataAutoDownloadActivity.this.selectedPreset;
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
                        if (a2 >= DataAutoDownloadActivity.this.presets.size()) {
                            break;
                        }
                        int i4 = this.sideSide;
                        int i5 = this.lineSize;
                        int i6 = this.gapSize;
                        int i7 = this.circleSize;
                        int cx2 = i4 + (((i6 * 2) + i5 + i7) * a2) + (i7 / 2);
                        int diff = (i5 / 2) + (i7 / 2) + i6;
                        if (x > cx2 - diff && x < cx2 + diff) {
                            if (DataAutoDownloadActivity.this.selectedPreset != a2) {
                                setPreset(a2);
                            }
                        } else {
                            a2++;
                        }
                    }
                }
            } else if (event.getAction() == 1 || event.getAction() == 3) {
                if (this.moving) {
                    if (DataAutoDownloadActivity.this.selectedPreset != this.startMovingPreset) {
                        setPreset(DataAutoDownloadActivity.this.selectedPreset);
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
                            if (DataAutoDownloadActivity.this.selectedPreset != a3) {
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
            DataAutoDownloadActivity.this.selectedPreset = index;
            DownloadController.Preset preset = (DownloadController.Preset) DataAutoDownloadActivity.this.presets.get(DataAutoDownloadActivity.this.selectedPreset);
            if (preset == DataAutoDownloadActivity.this.lowPreset) {
                DataAutoDownloadActivity.this.currentPresetNum = 0;
            } else if (preset == DataAutoDownloadActivity.this.mediumPreset) {
                DataAutoDownloadActivity.this.currentPresetNum = 1;
            } else if (preset == DataAutoDownloadActivity.this.highPreset) {
                DataAutoDownloadActivity.this.currentPresetNum = 2;
            } else {
                DataAutoDownloadActivity.this.currentPresetNum = 3;
            }
            if (DataAutoDownloadActivity.this.currentType == 0) {
                DownloadController.getInstance(DataAutoDownloadActivity.this.currentAccount).currentMobilePreset = DataAutoDownloadActivity.this.currentPresetNum;
            } else if (DataAutoDownloadActivity.this.currentType == 1) {
                DownloadController.getInstance(DataAutoDownloadActivity.this.currentAccount).currentWifiPreset = DataAutoDownloadActivity.this.currentPresetNum;
            } else {
                DownloadController.getInstance(DataAutoDownloadActivity.this.currentAccount).currentRoamingPreset = DataAutoDownloadActivity.this.currentPresetNum;
            }
            SharedPreferences.Editor editor = MessagesController.getMainSettings(DataAutoDownloadActivity.this.currentAccount).edit();
            editor.putInt(DataAutoDownloadActivity.this.key2, DataAutoDownloadActivity.this.currentPresetNum);
            editor.commit();
            DownloadController.getInstance(DataAutoDownloadActivity.this.currentAccount).checkAutodownloadSettings();
            for (int a = 0; a < 3; a++) {
                RecyclerView.ViewHolder holder = DataAutoDownloadActivity.this.listView.findViewHolderForAdapterPosition(DataAutoDownloadActivity.this.photosRow + a);
                if (holder != null) {
                    DataAutoDownloadActivity.this.listAdapter.onBindViewHolder(holder, DataAutoDownloadActivity.this.photosRow + a);
                }
            }
            DataAutoDownloadActivity.this.wereAnyChanges = true;
            invalidate();
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(74.0f), 1073741824));
            View.MeasureSpec.getSize(widthMeasureSpec);
            this.circleSize = AndroidUtilities.dp(6.0f);
            this.gapSize = AndroidUtilities.dp(2.0f);
            this.sideSide = AndroidUtilities.dp(22.0f);
            this.lineSize = (((getMeasuredWidth() - (this.circleSize * DataAutoDownloadActivity.this.presets.size())) - ((this.gapSize * 2) * (DataAutoDownloadActivity.this.presets.size() - 1))) - (this.sideSide * 2)) / (DataAutoDownloadActivity.this.presets.size() - 1);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            String text;
            int size;
            this.textPaint.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
            int cy = (getMeasuredHeight() / 2) + AndroidUtilities.dp(11.0f);
            int a = 0;
            while (a < DataAutoDownloadActivity.this.presets.size()) {
                int i = this.sideSide;
                int i2 = this.lineSize + (this.gapSize * 2);
                int i3 = this.circleSize;
                int cx = i + ((i2 + i3) * a) + (i3 / 2);
                if (a <= DataAutoDownloadActivity.this.selectedPreset) {
                    this.paint.setColor(Theme.getColor(Theme.key_switchTrackChecked));
                } else {
                    this.paint.setColor(Theme.getColor(Theme.key_switchTrack));
                }
                canvas.drawCircle(cx, cy, a == DataAutoDownloadActivity.this.selectedPreset ? AndroidUtilities.dp(6.0f) : this.circleSize / 2, this.paint);
                if (a != 0) {
                    int x = ((cx - (this.circleSize / 2)) - this.gapSize) - this.lineSize;
                    int width = this.lineSize;
                    if (a == DataAutoDownloadActivity.this.selectedPreset || a == DataAutoDownloadActivity.this.selectedPreset + 1) {
                        width -= AndroidUtilities.dp(3.0f);
                    }
                    if (a == DataAutoDownloadActivity.this.selectedPreset + 1) {
                        x += AndroidUtilities.dp(3.0f);
                    }
                    canvas.drawRect(x, cy - AndroidUtilities.dp(1.0f), x + width, AndroidUtilities.dp(1.0f) + cy, this.paint);
                }
                DownloadController.Preset preset = (DownloadController.Preset) DataAutoDownloadActivity.this.presets.get(a);
                if (preset != DataAutoDownloadActivity.this.lowPreset) {
                    if (preset != DataAutoDownloadActivity.this.mediumPreset) {
                        if (preset == DataAutoDownloadActivity.this.highPreset) {
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
                    if (a == DataAutoDownloadActivity.this.presets.size() - 1) {
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

    public DataAutoDownloadActivity(int type) {
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
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.DataAutoDownloadActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    DataAutoDownloadActivity.this.finishFragment();
                }
            }
        });
        this.listAdapter = new ListAdapter(context);
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setVerticalScrollBarEnabled(false);
        ((DefaultItemAnimator) this.listView.getItemAnimator()).setDelayAnimations(false);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false);
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1, 51));
        this.listView.setAdapter(this.listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListenerExtended() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DataAutoDownloadActivity$7TG5wkLg6dySCTJeg1zN5sZvLMg
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListenerExtended
            public final void onItemClick(View view, int i2, float f, float f2) {
                this.f$0.lambda$createView$4$DataAutoDownloadActivity(view, i2, f, f2);
            }
        });
        return this.fragmentView;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v21 */
    /* JADX WARN: Type inference failed for: r1v22, types: [boolean] */
    /* JADX WARN: Type inference failed for: r1v23 */
    public /* synthetic */ void lambda$createView$4$DataAutoDownloadActivity(final View view, final int i, float f, float f2) {
        int i2;
        DownloadController.Preset currentRoamingPreset;
        String str;
        String str2;
        DownloadController.Preset preset;
        LinearLayout linearLayout;
        ?? r1;
        ArrayList arrayList;
        NotificationsCheckCell notificationsCheckCell;
        DataAutoDownloadActivity dataAutoDownloadActivity = this;
        int i3 = i;
        int i4 = 4;
        if (i3 == dataAutoDownloadActivity.autoDownloadRow) {
            int i5 = dataAutoDownloadActivity.currentPresetNum;
            if (i5 != 3) {
                if (i5 == 0) {
                    dataAutoDownloadActivity.typePreset.set(dataAutoDownloadActivity.lowPreset);
                } else if (i5 == 1) {
                    dataAutoDownloadActivity.typePreset.set(dataAutoDownloadActivity.mediumPreset);
                } else if (i5 == 2) {
                    dataAutoDownloadActivity.typePreset.set(dataAutoDownloadActivity.highPreset);
                }
            }
            TextCheckCell textCheckCell = (TextCheckCell) view;
            boolean zIsChecked = textCheckCell.isChecked();
            if (!zIsChecked && dataAutoDownloadActivity.typePreset.enabled) {
                System.arraycopy(dataAutoDownloadActivity.defaultPreset.mask, 0, dataAutoDownloadActivity.typePreset.mask, 0, 4);
            } else {
                dataAutoDownloadActivity.typePreset.enabled = !r2.enabled;
            }
            boolean z = dataAutoDownloadActivity.typePreset.enabled;
            String str3 = Theme.key_windowBackgroundChecked;
            view.setTag(z ? Theme.key_windowBackgroundChecked : Theme.key_windowBackgroundUnchecked);
            boolean z2 = !zIsChecked;
            if (!dataAutoDownloadActivity.typePreset.enabled) {
                str3 = Theme.key_windowBackgroundUnchecked;
            }
            textCheckCell.setBackgroundColorAnimated(z2, Theme.getColor(str3));
            updateRows();
            if (dataAutoDownloadActivity.typePreset.enabled) {
                dataAutoDownloadActivity.listAdapter.notifyItemRangeInserted(dataAutoDownloadActivity.autoDownloadSectionRow + 1, 8);
            } else {
                dataAutoDownloadActivity.listAdapter.notifyItemRangeRemoved(dataAutoDownloadActivity.autoDownloadSectionRow + 1, 8);
            }
            dataAutoDownloadActivity.listAdapter.notifyItemChanged(dataAutoDownloadActivity.autoDownloadSectionRow);
            SharedPreferences.Editor editorEdit = MessagesController.getMainSettings(dataAutoDownloadActivity.currentAccount).edit();
            editorEdit.putString(dataAutoDownloadActivity.key, dataAutoDownloadActivity.typePreset.toString());
            String str4 = dataAutoDownloadActivity.key2;
            dataAutoDownloadActivity.currentPresetNum = 3;
            editorEdit.putInt(str4, 3);
            int i6 = dataAutoDownloadActivity.currentType;
            if (i6 == 0) {
                DownloadController.getInstance(dataAutoDownloadActivity.currentAccount).currentMobilePreset = dataAutoDownloadActivity.currentPresetNum;
            } else if (i6 == 1) {
                DownloadController.getInstance(dataAutoDownloadActivity.currentAccount).currentWifiPreset = dataAutoDownloadActivity.currentPresetNum;
            } else {
                DownloadController.getInstance(dataAutoDownloadActivity.currentAccount).currentRoamingPreset = dataAutoDownloadActivity.currentPresetNum;
            }
            editorEdit.commit();
            textCheckCell.setChecked(!zIsChecked);
            DownloadController.getInstance(dataAutoDownloadActivity.currentAccount).checkAutodownloadSettings();
            dataAutoDownloadActivity.wereAnyChanges = true;
            return;
        }
        if ((i3 != dataAutoDownloadActivity.photosRow && i3 != dataAutoDownloadActivity.videosRow && i3 != dataAutoDownloadActivity.filesRow) || !view.isEnabled()) {
            return;
        }
        if (i3 == dataAutoDownloadActivity.photosRow) {
            i2 = 1;
        } else if (i3 == dataAutoDownloadActivity.videosRow) {
            i2 = 4;
        } else {
            i2 = 8;
        }
        final int iTypeToIndex = DownloadController.typeToIndex(i2);
        int i7 = dataAutoDownloadActivity.currentType;
        if (i7 == 0) {
            currentRoamingPreset = DownloadController.getInstance(dataAutoDownloadActivity.currentAccount).getCurrentMobilePreset();
            str = "mobilePreset";
            str2 = "currentMobilePreset";
        } else if (i7 == 1) {
            currentRoamingPreset = DownloadController.getInstance(dataAutoDownloadActivity.currentAccount).getCurrentWiFiPreset();
            str = "wifiPreset";
            str2 = "currentWifiPreset";
        } else {
            currentRoamingPreset = DownloadController.getInstance(dataAutoDownloadActivity.currentAccount).getCurrentRoamingPreset();
            str = "roamingPreset";
            str2 = "currentRoamingPreset";
        }
        NotificationsCheckCell notificationsCheckCell2 = (NotificationsCheckCell) view;
        boolean zIsChecked2 = notificationsCheckCell2.isChecked();
        if ((LocaleController.isRTL && f <= AndroidUtilities.dp(76.0f)) || (!LocaleController.isRTL && f >= view.getMeasuredWidth() - AndroidUtilities.dp(76.0f))) {
            int i8 = dataAutoDownloadActivity.currentPresetNum;
            if (i8 != 3) {
                if (i8 == 0) {
                    dataAutoDownloadActivity.typePreset.set(dataAutoDownloadActivity.lowPreset);
                } else if (i8 == 1) {
                    dataAutoDownloadActivity.typePreset.set(dataAutoDownloadActivity.mediumPreset);
                } else if (i8 == 2) {
                    dataAutoDownloadActivity.typePreset.set(dataAutoDownloadActivity.highPreset);
                }
            }
            boolean z3 = false;
            int i9 = 0;
            while (true) {
                if (i9 >= dataAutoDownloadActivity.typePreset.mask.length) {
                    break;
                }
                if ((currentRoamingPreset.mask[i9] & i2) == 0) {
                    i9++;
                } else {
                    z3 = true;
                    break;
                }
            }
            for (int i10 = 0; i10 < dataAutoDownloadActivity.typePreset.mask.length; i10++) {
                if (zIsChecked2) {
                    int[] iArr = dataAutoDownloadActivity.typePreset.mask;
                    iArr[i10] = iArr[i10] & (~i2);
                } else if (!z3) {
                    int[] iArr2 = dataAutoDownloadActivity.typePreset.mask;
                    iArr2[i10] = iArr2[i10] | i2;
                }
            }
            SharedPreferences.Editor editorEdit2 = MessagesController.getMainSettings(dataAutoDownloadActivity.currentAccount).edit();
            editorEdit2.putString(str, dataAutoDownloadActivity.typePreset.toString());
            dataAutoDownloadActivity.currentPresetNum = 3;
            editorEdit2.putInt(str2, 3);
            int i11 = dataAutoDownloadActivity.currentType;
            if (i11 == 0) {
                DownloadController.getInstance(dataAutoDownloadActivity.currentAccount).currentMobilePreset = dataAutoDownloadActivity.currentPresetNum;
            } else if (i11 == 1) {
                DownloadController.getInstance(dataAutoDownloadActivity.currentAccount).currentWifiPreset = dataAutoDownloadActivity.currentPresetNum;
            } else {
                DownloadController.getInstance(dataAutoDownloadActivity.currentAccount).currentRoamingPreset = dataAutoDownloadActivity.currentPresetNum;
            }
            editorEdit2.commit();
            notificationsCheckCell2.setChecked(!zIsChecked2);
            RecyclerView.ViewHolder viewHolderFindContainingViewHolder = dataAutoDownloadActivity.listView.findContainingViewHolder(view);
            if (viewHolderFindContainingViewHolder != null) {
                dataAutoDownloadActivity.listAdapter.onBindViewHolder(viewHolderFindContainingViewHolder, i3);
            }
            DownloadController.getInstance(dataAutoDownloadActivity.currentAccount).checkAutodownloadSettings();
            dataAutoDownloadActivity.wereAnyChanges = true;
            fillPresets();
            return;
        }
        if (getParentActivity() == null) {
            return;
        }
        BottomSheet.Builder builder = new BottomSheet.Builder(getParentActivity());
        builder.setApplyTopPadding(false);
        builder.setApplyBottomPadding(false);
        LinearLayout linearLayout2 = new LinearLayout(getParentActivity());
        linearLayout2.setOrientation(1);
        builder.setCustomView(linearLayout2);
        HeaderCell headerCell = new HeaderCell(getParentActivity(), true, 21, 15, false);
        if (i3 == dataAutoDownloadActivity.photosRow) {
            headerCell.setText(LocaleController.getString("AutoDownloadPhotosTitle", R.string.AutoDownloadPhotosTitle));
        } else if (i3 == dataAutoDownloadActivity.videosRow) {
            headerCell.setText(LocaleController.getString("AutoDownloadVideosTitle", R.string.AutoDownloadVideosTitle));
        } else {
            headerCell.setText(LocaleController.getString("AutoDownloadFilesTitle", R.string.AutoDownloadFilesTitle));
        }
        linearLayout2.addView(headerCell, LayoutHelper.createFrame(-1, -2.0f));
        final MaxFileSizeCell[] maxFileSizeCellArr = new MaxFileSizeCell[1];
        final TextCheckCell[] textCheckCellArr = new TextCheckCell[1];
        final AnimatorSet[] animatorSetArr = new AnimatorSet[1];
        final TextCheckBoxCell[] textCheckBoxCellArr = new TextCheckBoxCell[4];
        int i12 = 0;
        while (i12 < i4) {
            LinearLayout linearLayout3 = linearLayout2;
            BottomSheet.Builder builder2 = builder;
            final TextCheckBoxCell textCheckBoxCell = new TextCheckBoxCell(getParentActivity(), true);
            textCheckBoxCellArr[i12] = textCheckBoxCell;
            HeaderCell headerCell2 = headerCell;
            if (i12 == 0) {
                notificationsCheckCell = notificationsCheckCell2;
                textCheckBoxCellArr[i12].setTextAndCheck(LocaleController.getString("AutodownloadContacts", R.string.AutodownloadContacts), (currentRoamingPreset.mask[0] & i2) != 0, true);
            } else {
                notificationsCheckCell = notificationsCheckCell2;
                if (i12 == 1) {
                    textCheckBoxCellArr[i12].setTextAndCheck(LocaleController.getString("AutodownloadPrivateChats", R.string.AutodownloadPrivateChats), (currentRoamingPreset.mask[1] & i2) != 0, true);
                } else if (i12 == 2) {
                    textCheckBoxCellArr[i12].setTextAndCheck(LocaleController.getString("AutodownloadGroupChats", R.string.AutodownloadGroupChats), (currentRoamingPreset.mask[2] & i2) != 0, true);
                } else if (i12 == 3) {
                    textCheckBoxCellArr[i12].setTextAndCheck(LocaleController.getString("AutodownloadChannels", R.string.AutodownloadChannels), (currentRoamingPreset.mask[3] & i2) != 0, i3 != dataAutoDownloadActivity.photosRow);
                }
            }
            textCheckBoxCellArr[i12].setBackgroundDrawable(Theme.getSelectorDrawable(false));
            textCheckBoxCellArr[i12].setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DataAutoDownloadActivity$5AMX8eOoocvc45Al6bvkywbp6Rk
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$null$0$DataAutoDownloadActivity(textCheckBoxCell, textCheckBoxCellArr, i, maxFileSizeCellArr, textCheckCellArr, animatorSetArr, view2);
                }
            });
            linearLayout3.addView(textCheckBoxCellArr[i12], LayoutHelper.createFrame(-1, 50.0f));
            i12++;
            dataAutoDownloadActivity = this;
            linearLayout2 = linearLayout3;
            notificationsCheckCell2 = notificationsCheckCell;
            str2 = str2;
            headerCell = headerCell2;
            str = str;
            builder = builder2;
            currentRoamingPreset = currentRoamingPreset;
            i2 = i2;
            i4 = 4;
            i3 = i;
        }
        LinearLayout linearLayout4 = linearLayout2;
        final BottomSheet.Builder builder3 = builder;
        final String str5 = str2;
        final String str6 = str;
        DownloadController.Preset preset2 = currentRoamingPreset;
        final int i13 = i2;
        if (i != this.photosRow) {
            final TextInfoPrivacyCell textInfoPrivacyCell = new TextInfoPrivacyCell(getParentActivity());
            LinearLayout linearLayout5 = linearLayout4;
            maxFileSizeCellArr[0] = new MaxFileSizeCell(getParentActivity(), false) { // from class: im.uwrkaxlmjj.ui.DataAutoDownloadActivity.3
                @Override // im.uwrkaxlmjj.ui.cells.MaxFileSizeCell
                protected void didChangedSizeValue(int value) {
                    if (i == DataAutoDownloadActivity.this.videosRow) {
                        textInfoPrivacyCell.setText(LocaleController.formatString("AutoDownloadPreloadVideoInfo", R.string.AutoDownloadPreloadVideoInfo, AndroidUtilities.formatFileSize(value)));
                        boolean enabled = value > 2097152;
                        if (enabled != textCheckCellArr[0].isEnabled()) {
                            ArrayList<Animator> arrayList2 = new ArrayList<>();
                            textCheckCellArr[0].setEnabled(enabled, arrayList2);
                            AnimatorSet[] animatorSetArr2 = animatorSetArr;
                            if (animatorSetArr2[0] != null) {
                                animatorSetArr2[0].cancel();
                                animatorSetArr[0] = null;
                            }
                            animatorSetArr[0] = new AnimatorSet();
                            animatorSetArr[0].playTogether(arrayList2);
                            animatorSetArr[0].addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.DataAutoDownloadActivity.3.1
                                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                                public void onAnimationEnd(Animator animator) {
                                    if (animator.equals(animatorSetArr[0])) {
                                        animatorSetArr[0] = null;
                                    }
                                }
                            });
                            animatorSetArr[0].setDuration(150L);
                            animatorSetArr[0].start();
                        }
                    }
                }
            };
            preset = preset2;
            maxFileSizeCellArr[0].setSize(preset.sizes[iTypeToIndex]);
            linearLayout5.addView(maxFileSizeCellArr[0], LayoutHelper.createLinear(-1, 50));
            linearLayout5.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            textCheckCellArr[0] = new TextCheckCell(getParentActivity(), 21, true);
            linearLayout5.addView(textCheckCellArr[0], LayoutHelper.createLinear(-1, 48));
            textCheckCellArr[0].setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DataAutoDownloadActivity$eHkbMvg2avJbsA3RtTIBOBCJlWI
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    textCheckCellArr[0].setChecked(!r0[0].isChecked());
                }
            });
            CombinedDrawable combinedDrawable = new CombinedDrawable(new ColorDrawable(Theme.getColor(Theme.key_windowBackgroundGray)), Theme.getThemedDrawable(getParentActivity(), R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
            combinedDrawable.setFullsize(true);
            textInfoPrivacyCell.setBackgroundDrawable(combinedDrawable);
            linearLayout5.addView(textInfoPrivacyCell, LayoutHelper.createLinear(-1, -2));
            if (i == this.videosRow) {
                maxFileSizeCellArr[0].setText(LocaleController.getString("AutoDownloadMaxVideoSize", R.string.AutoDownloadMaxVideoSize));
                textCheckCellArr[0].setTextAndCheck(LocaleController.getString("AutoDownloadPreloadVideo", R.string.AutoDownloadPreloadVideo), preset.preloadVideo, false);
                textInfoPrivacyCell.setText(LocaleController.formatString("AutoDownloadPreloadVideoInfo", R.string.AutoDownloadPreloadVideoInfo, AndroidUtilities.formatFileSize(preset.sizes[iTypeToIndex])));
                linearLayout = linearLayout5;
            } else {
                maxFileSizeCellArr[0].setText(LocaleController.getString("AutoDownloadMaxFileSize", R.string.AutoDownloadMaxFileSize));
                textCheckCellArr[0].setTextAndCheck(LocaleController.getString("AutoDownloadPreloadMusic", R.string.AutoDownloadPreloadMusic), preset.preloadMusic, false);
                textInfoPrivacyCell.setText(LocaleController.getString("AutoDownloadPreloadMusicInfo", R.string.AutoDownloadPreloadMusicInfo));
                linearLayout = linearLayout5;
            }
        } else {
            LinearLayout linearLayout6 = linearLayout4;
            preset = preset2;
            maxFileSizeCellArr[0] = null;
            textCheckCellArr[0] = 0;
            View view2 = new View(getParentActivity());
            view2.setBackgroundColor(Theme.getColor(Theme.key_divider));
            linearLayout6.addView(view2, new LinearLayout.LayoutParams(-1, 1));
            linearLayout = linearLayout6;
        }
        if (i == this.videosRow) {
            boolean z4 = false;
            int i14 = 0;
            while (true) {
                if (i14 >= textCheckBoxCellArr.length) {
                    break;
                }
                if (!textCheckBoxCellArr[i14].isChecked()) {
                    i14++;
                } else {
                    z4 = true;
                    break;
                }
            }
            if (z4) {
                r1 = 0;
                arrayList = null;
            } else {
                r1 = 0;
                arrayList = null;
                maxFileSizeCellArr[0].setEnabled(z4, null);
                textCheckCellArr[0].setEnabled(z4, null);
            }
            if (preset.sizes[iTypeToIndex] <= 2097152) {
                textCheckCellArr[r1].setEnabled(r1, arrayList);
            }
        }
        FrameLayout frameLayout = new FrameLayout(getParentActivity());
        frameLayout.setPadding(AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f));
        linearLayout.addView(frameLayout, LayoutHelper.createLinear(-1, 52));
        TextView textView = new TextView(getParentActivity());
        textView.setTextSize(1, 14.0f);
        textView.setTextColor(Theme.getColor(Theme.key_dialogTextBlue2));
        textView.setGravity(17);
        textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        textView.setText(LocaleController.getString("Cancel", R.string.Cancel).toUpperCase());
        textView.setPadding(AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0);
        frameLayout.addView(textView, LayoutHelper.createFrame(-2, 36, 51));
        textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DataAutoDownloadActivity$wC8s4EFUtSjEMSe7X25byGw_020
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                builder3.getDismissRunnable().run();
            }
        });
        TextView textView2 = new TextView(getParentActivity());
        textView2.setTextSize(1, 14.0f);
        textView2.setTextColor(Theme.getColor(Theme.key_dialogTextBlue2));
        textView2.setGravity(17);
        textView2.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        textView2.setText(LocaleController.getString("Save", R.string.Save).toUpperCase());
        textView2.setPadding(AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0);
        frameLayout.addView(textView2, LayoutHelper.createFrame(-2, 36, 53));
        textView2.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DataAutoDownloadActivity$0b2Q6AwSijFP3qYkk82824wp9nE
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$null$3$DataAutoDownloadActivity(textCheckBoxCellArr, i13, maxFileSizeCellArr, iTypeToIndex, textCheckCellArr, i, str6, str5, builder3, view, view3);
            }
        });
        showDialog(builder3.create());
    }

    public /* synthetic */ void lambda$null$0$DataAutoDownloadActivity(TextCheckBoxCell checkBoxCell, TextCheckBoxCell[] cells, int position, MaxFileSizeCell[] sizeCell, TextCheckCell[] checkCell, final AnimatorSet[] animatorSet, View v) {
        if (!v.isEnabled()) {
            return;
        }
        checkBoxCell.setChecked(!checkBoxCell.isChecked());
        boolean hasAny = false;
        int b = 0;
        while (true) {
            if (b >= cells.length) {
                break;
            }
            if (!cells[b].isChecked()) {
                b++;
            } else {
                hasAny = true;
                break;
            }
        }
        int b2 = this.videosRow;
        if (position == b2 && sizeCell[0].isEnabled() != hasAny) {
            ArrayList<Animator> animators = new ArrayList<>();
            sizeCell[0].setEnabled(hasAny, animators);
            if (sizeCell[0].getSize() > 2097152) {
                checkCell[0].setEnabled(hasAny, animators);
            }
            if (animatorSet[0] != null) {
                animatorSet[0].cancel();
                animatorSet[0] = null;
            }
            animatorSet[0] = new AnimatorSet();
            animatorSet[0].playTogether(animators);
            animatorSet[0].addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.DataAutoDownloadActivity.2
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animator) {
                    if (animator.equals(animatorSet[0])) {
                        animatorSet[0] = null;
                    }
                }
            });
            animatorSet[0].setDuration(150L);
            animatorSet[0].start();
        }
    }

    public /* synthetic */ void lambda$null$3$DataAutoDownloadActivity(TextCheckBoxCell[] cells, int type, MaxFileSizeCell[] sizeCell, int index, TextCheckCell[] checkCell, int position, String key, String key2, BottomSheet.Builder builder, View view, View v1) {
        int i = this.currentPresetNum;
        if (i != 3) {
            if (i == 0) {
                this.typePreset.set(this.lowPreset);
            } else if (i == 1) {
                this.typePreset.set(this.mediumPreset);
            } else if (i == 2) {
                this.typePreset.set(this.highPreset);
            }
        }
        for (int a = 0; a < 4; a++) {
            if (cells[a].isChecked()) {
                int[] iArr = this.typePreset.mask;
                iArr[a] = iArr[a] | type;
            } else {
                int[] iArr2 = this.typePreset.mask;
                iArr2[a] = iArr2[a] & (~type);
            }
        }
        if (sizeCell[0] != null) {
            this.typePreset.sizes[index] = (int) sizeCell[0].getSize();
        }
        if (checkCell[0] != null) {
            if (position == this.videosRow) {
                this.typePreset.preloadVideo = checkCell[0].isChecked();
            } else {
                this.typePreset.preloadMusic = checkCell[0].isChecked();
            }
        }
        SharedPreferences.Editor editor = MessagesController.getMainSettings(this.currentAccount).edit();
        editor.putString(key, this.typePreset.toString());
        this.currentPresetNum = 3;
        editor.putInt(key2, 3);
        int i2 = this.currentType;
        if (i2 == 0) {
            DownloadController.getInstance(this.currentAccount).currentMobilePreset = this.currentPresetNum;
        } else if (i2 == 1) {
            DownloadController.getInstance(this.currentAccount).currentWifiPreset = this.currentPresetNum;
        } else {
            DownloadController.getInstance(this.currentAccount).currentRoamingPreset = this.currentPresetNum;
        }
        editor.commit();
        builder.getDismissRunnable().run();
        RecyclerView.ViewHolder holder = this.listView.findContainingViewHolder(view);
        if (holder != null) {
            this.animateChecked = true;
            this.listAdapter.onBindViewHolder(holder, position);
            this.animateChecked = false;
        }
        DownloadController.getInstance(this.currentAccount).checkAutodownloadSettings();
        this.wereAnyChanges = true;
        fillPresets();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
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

    private void fillPresets() {
        this.presets.clear();
        this.presets.add(this.lowPreset);
        this.presets.add(this.mediumPreset);
        this.presets.add(this.highPreset);
        if (!this.typePreset.equals(this.lowPreset) && !this.typePreset.equals(this.mediumPreset) && !this.typePreset.equals(this.highPreset)) {
            this.presets.add(this.typePreset);
        }
        Collections.sort(this.presets, new Comparator() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DataAutoDownloadActivity$5QrHX6rWoxgalBDU8j5ZMh09014
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return DataAutoDownloadActivity.lambda$fillPresets$5((DownloadController.Preset) obj, (DownloadController.Preset) obj2);
            }
        });
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            RecyclerView.ViewHolder holder = recyclerListView.findViewHolderForAdapterPosition(this.usageProgressRow);
            if (holder != null) {
                holder.itemView.requestLayout();
            } else {
                this.listAdapter.notifyItemChanged(this.usageProgressRow);
            }
        }
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

    static /* synthetic */ int lambda$fillPresets$5(DownloadController.Preset o1, DownloadController.Preset o2) {
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

    private void updateRows() {
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

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return DataAutoDownloadActivity.this.rowCount;
        }

        /* JADX WARN: Removed duplicated region for block: B:76:0x0226  */
        /* JADX WARN: Removed duplicated region for block: B:81:0x0230  */
        /* JADX WARN: Removed duplicated region for block: B:82:0x0232  */
        /* JADX WARN: Removed duplicated region for block: B:85:0x023e  */
        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void onBindViewHolder(androidx.recyclerview.widget.RecyclerView.ViewHolder r19, int r20) {
            /*
                Method dump skipped, instruction units count: 712
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.DataAutoDownloadActivity.ListAdapter.onBindViewHolder(androidx.recyclerview.widget.RecyclerView$ViewHolder, int):void");
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return position == DataAutoDownloadActivity.this.photosRow || position == DataAutoDownloadActivity.this.videosRow || position == DataAutoDownloadActivity.this.filesRow;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                TextCheckCell cell = new TextCheckCell(this.mContext);
                cell.setColors(Theme.key_windowBackgroundCheckText, Theme.key_switchTrackBlue, Theme.key_switchTrackBlueChecked, Theme.key_switchTrackBlueThumb, Theme.key_switchTrackBlueThumbChecked);
                cell.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                cell.setHeight(56);
                view = cell;
                RecyclerView.LayoutParams layoutParams = new RecyclerView.LayoutParams(-1, -2);
                layoutParams.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams);
            } else if (viewType == 1) {
                view = new ShadowSectionCell(this.mContext);
                RecyclerView.LayoutParams layoutParams2 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams2.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams2.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams2);
            } else if (viewType == 2) {
                view = new HeaderCell(this.mContext);
                RecyclerView.LayoutParams layoutParams3 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams3.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams3.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams3);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 3) {
                view = DataAutoDownloadActivity.this.new PresetChooseView(this.mContext);
                RecyclerView.LayoutParams layoutParams4 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams4.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams4.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams4);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 4) {
                view = new NotificationsCheckCell(this.mContext);
                RecyclerView.LayoutParams layoutParams5 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams5.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams5.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams5);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 5) {
                view = new TextInfoPrivacyCell(this.mContext);
                RecyclerView.LayoutParams layoutParams6 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams6.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams6.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams6);
                view.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
            }
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != DataAutoDownloadActivity.this.autoDownloadRow) {
                if (position != DataAutoDownloadActivity.this.usageSectionRow) {
                    if (position != DataAutoDownloadActivity.this.usageHeaderRow && position != DataAutoDownloadActivity.this.typeHeaderRow) {
                        if (position != DataAutoDownloadActivity.this.usageProgressRow) {
                            if (position == DataAutoDownloadActivity.this.photosRow || position == DataAutoDownloadActivity.this.videosRow || position == DataAutoDownloadActivity.this.filesRow) {
                                return 4;
                            }
                            return 5;
                        }
                        return 3;
                    }
                    return 2;
                }
                return 1;
            }
            return 0;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{HeaderCell.class, NotificationsCheckCell.class, PresetChooseView.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{TextCheckCell.class}, null, null, null, Theme.key_windowBackgroundChecked), new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{TextCheckCell.class}, null, null, null, Theme.key_windowBackgroundUnchecked), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundCheckText), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackBlue), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackBlueChecked), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackBlueThumb), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackBlueThumbChecked), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackBlueSelector), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackBlueSelectorChecked), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrack), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackChecked), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, 0, new Class[]{PresetChooseView.class}, null, null, null, Theme.key_switchTrack), new ThemeDescription(this.listView, 0, new Class[]{PresetChooseView.class}, null, null, null, Theme.key_switchTrackChecked), new ThemeDescription(this.listView, 0, new Class[]{PresetChooseView.class}, null, null, null, Theme.key_windowBackgroundWhiteGrayText)};
    }
}
