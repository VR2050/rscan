package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.TextUtils;
import android.text.style.ForegroundColorSpan;
import android.util.LongSparseArray;
import android.util.Property;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.WindowManager;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.core.internal.view.SupportMenu;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.WallpaperActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.GraySectionCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.WallpaperCell;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.NumberTextView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.WallpaperUpdater;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WallpapersListActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    public static final int TYPE_ALL = 0;
    public static final int TYPE_COLOR = 1;
    private static final int delete = 4;
    private static final int forward = 3;
    private ColorWallpaper addedColorWallpaper;
    private FileWallpaper addedFileWallpaper;
    private FileWallpaper catsWallpaper;
    private Paint colorFramePaint;
    private Paint colorPaint;
    private int currentType;
    private LinearLayoutManager layoutManager;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private boolean loadingWallpapers;
    private AlertDialog progressDialog;
    private int resetInfoRow;
    private int resetRow;
    private int resetSectionRow;
    private int rowCount;
    private boolean scrolling;
    private SearchAdapter searchAdapter;
    private EmptyTextProgressView searchEmptyView;
    private ActionBarMenuItem searchItem;
    private int sectionRow;
    private long selectedBackground;
    private boolean selectedBackgroundBlurred;
    private boolean selectedBackgroundMotion;
    private int selectedColor;
    private float selectedIntensity;
    private NumberTextView selectedMessagesCountTextView;
    private long selectedPattern;
    private int setColorRow;
    private FileWallpaper themeWallpaper;
    private int totalWallpaperRows;
    private WallpaperUpdater updater;
    private int uploadImageRow;
    private int wallPaperStartRow;
    private static final int[] defaultColors = {-1, -2826262, -4993567, -9783318, -16740912, -2891046, -3610935, -3808859, -10375058, -3289169, -5789547, -8622222, -10322, -18835, -2193583, -1059360, -2383431, -20561, -955808, -1524502, -6974739, -2507680, -5145015, -2765065, -2142101, -7613748, -12811138, -14524116, -14398084, -12764283, -10129027, -15195603, -16777216};
    private static final int[] searchColors = {-16746753, SupportMenu.CATEGORY_MASK, -30208, -13824, -16718798, -14702165, -9240406, -409915, -9224159, -16777216, -10725281, -1};
    private static final String[] searchColorsNames = {"Blue", "Red", "Orange", "Yellow", "Green", "Teal", "Purple", "Pink", "Brown", "Black", "Gray", "White"};
    private static final int[] searchColorsNamesR = {R.string.Blue, R.string.Red, R.string.Orange, R.string.Yellow, R.string.Green, R.string.Teal, R.string.Purple, R.string.Pink, R.string.Brown, R.string.Black, R.string.Gray, R.string.White};
    private ArrayList<View> actionModeViews = new ArrayList<>();
    private int columnsCount = 3;
    private ArrayList<Object> allWallPapers = new ArrayList<>();
    private LongSparseArray<Object> allWallPapersDict = new LongSparseArray<>();
    private ArrayList<Object> wallPapers = new ArrayList<>();
    private ArrayList<Object> patterns = new ArrayList<>();
    private LongSparseArray<Object> selectedWallPapers = new LongSparseArray<>();

    public static class ColorWallpaper {
        public int color;
        public long id;
        public float intensity;
        public boolean motion;
        public File path;
        public TLRPC.TL_wallPaper pattern;
        public long patternId;

        public ColorWallpaper(long i, int c) {
            this.id = i;
            this.color = (-16777216) | c;
            this.intensity = 1.0f;
        }

        public ColorWallpaper(long i, int c, long p, float in, boolean m, File ph) {
            this.id = i;
            this.color = (-16777216) | c;
            this.patternId = p;
            this.intensity = in;
            this.path = ph;
            this.motion = m;
        }
    }

    public static class FileWallpaper {
        public long id;
        public File originalPath;
        public File path;
        public int resId;
        public int thumbResId;

        public FileWallpaper(long i, File f, File of) {
            this.id = i;
            this.path = f;
            this.originalPath = of;
        }

        public FileWallpaper(long i, String f) {
            this.id = i;
            this.path = new File(f);
        }

        public FileWallpaper(long i, int r, int t) {
            this.id = i;
            this.resId = r;
            this.thumbResId = t;
        }
    }

    public WallpapersListActivity(int type) {
        this.currentType = type;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        if (this.currentType == 0) {
            NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.wallpapersDidLoad);
            NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.didSetNewWallpapper);
            NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.wallpapersNeedReload);
            MessagesStorage.getInstance(this.currentAccount).getWallpapers();
        } else {
            int a = 0;
            while (true) {
                int[] iArr = defaultColors;
                if (a >= iArr.length) {
                    break;
                }
                this.wallPapers.add(new ColorWallpaper(-(a + 3), iArr[a]));
                a++;
            }
            int a2 = this.currentType;
            if (a2 == 1 && this.patterns.isEmpty()) {
                NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.wallpapersDidLoad);
                MessagesStorage.getInstance(this.currentAccount).getWallpapers();
            }
        }
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        int i = this.currentType;
        if (i == 0) {
            this.searchAdapter.onDestroy();
            NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.wallpapersDidLoad);
            NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didSetNewWallpapper);
            NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.wallpapersNeedReload);
        } else if (i == 1) {
            NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.wallpapersDidLoad);
        }
        this.updater.cleanup();
        super.onFragmentDestroy();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        int i = 1;
        this.colorPaint = new Paint(1);
        Paint paint = new Paint(1);
        this.colorFramePaint = paint;
        paint.setStrokeWidth(AndroidUtilities.dp(1.0f));
        this.colorFramePaint.setStyle(Paint.Style.STROKE);
        this.colorFramePaint.setColor(Theme.value_blackAlpha80);
        this.updater = new WallpaperUpdater(getParentActivity(), this, new WallpaperUpdater.WallpaperUpdaterDelegate() { // from class: im.uwrkaxlmjj.ui.WallpapersListActivity.1
            @Override // im.uwrkaxlmjj.ui.components.WallpaperUpdater.WallpaperUpdaterDelegate
            public void didSelectWallpaper(File file, Bitmap bitmap, boolean gallery) {
                WallpapersListActivity.this.presentFragment(new WallpaperActivity(new FileWallpaper(-1L, file, file), bitmap), gallery);
            }

            @Override // im.uwrkaxlmjj.ui.components.WallpaperUpdater.WallpaperUpdaterDelegate
            public void needOpenColorPicker() {
            }
        });
        this.hasOwnBackground = true;
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        int i2 = this.currentType;
        if (i2 == 0) {
            this.actionBar.setTitle(LocaleController.getString("ChatBackground", R.string.ChatBackground));
        } else if (i2 == 1) {
            this.actionBar.setTitle(LocaleController.getString("SelectColorTitle", R.string.SelectColorTitle));
        }
        this.actionBar.setActionBarMenuOnItemClick(new AnonymousClass2());
        boolean z = false;
        if (this.currentType == 0) {
            ActionBarMenu menu = this.actionBar.createMenu();
            ActionBarMenuItem actionBarMenuItemSearchListener = menu.addItem(0, R.drawable.ic_ab_search).setIsSearchField(true).setActionBarMenuItemSearchListener(new ActionBarMenuItem.ActionBarMenuItemSearchListener() { // from class: im.uwrkaxlmjj.ui.WallpapersListActivity.3
                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
                public void onSearchExpand() {
                    WallpapersListActivity.this.listView.setAdapter(WallpapersListActivity.this.searchAdapter);
                    WallpapersListActivity.this.listView.invalidate();
                }

                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
                public void onSearchCollapse() {
                    WallpapersListActivity.this.listView.setAdapter(WallpapersListActivity.this.listAdapter);
                    WallpapersListActivity.this.listView.invalidate();
                    WallpapersListActivity.this.searchAdapter.processSearch(null, true);
                    WallpapersListActivity.this.searchItem.setSearchFieldCaption(null);
                    onCaptionCleared();
                }

                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
                public void onTextChanged(EditText editText) {
                    WallpapersListActivity.this.searchAdapter.processSearch(editText.getText().toString(), false);
                }

                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
                public void onCaptionCleared() {
                    WallpapersListActivity.this.searchAdapter.clearColor();
                    WallpapersListActivity.this.searchItem.setSearchFieldHint(LocaleController.getString("SearchBackgrounds", R.string.SearchBackgrounds));
                    if (WallpapersListActivity.this.searchAdapter == null) {
                        return;
                    }
                    WallpapersListActivity.this.searchAdapter.cancelSearchingUser();
                }
            });
            this.searchItem = actionBarMenuItemSearchListener;
            actionBarMenuItemSearchListener.setSearchFieldHint(LocaleController.getString("SearchBackgrounds", R.string.SearchBackgrounds));
            ActionBarMenu actionMode = this.actionBar.createActionMode(false);
            actionMode.setBackgroundColor(Theme.getColor(Theme.key_actionBarDefault));
            this.actionBar.setItemsColor(Theme.getColor(Theme.key_actionBarDefaultIcon), true);
            this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_actionBarDefaultSelector), true);
            NumberTextView numberTextView = new NumberTextView(actionMode.getContext());
            this.selectedMessagesCountTextView = numberTextView;
            numberTextView.setTextSize(18);
            this.selectedMessagesCountTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.selectedMessagesCountTextView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultIcon));
            this.selectedMessagesCountTextView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$hFC_nqBOfSQiVg2UNeSvdWpdvW4
                @Override // android.view.View.OnTouchListener
                public final boolean onTouch(View view, MotionEvent motionEvent) {
                    return WallpapersListActivity.lambda$createView$0(view, motionEvent);
                }
            });
            actionMode.addView(this.selectedMessagesCountTextView, LayoutHelper.createLinear(0, -1, 1.0f, 65, 0, 0, 0));
            this.actionModeViews.add(actionMode.addItemWithWidth(3, R.drawable.msg_forward, AndroidUtilities.dp(54.0f)));
            this.actionModeViews.add(actionMode.addItemWithWidth(4, R.drawable.msg_delete, AndroidUtilities.dp(54.0f)));
            this.selectedWallPapers.clear();
        }
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.WallpapersListActivity.4
            private Paint paint = new Paint();

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, android.view.View
            public boolean hasOverlappingRendering() {
                return false;
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
            public void onDraw(Canvas c) {
                RecyclerView.ViewHolder holder;
                int bottom;
                if (getAdapter() == WallpapersListActivity.this.listAdapter && WallpapersListActivity.this.resetInfoRow != -1) {
                    holder = findViewHolderForAdapterPosition(WallpapersListActivity.this.resetInfoRow);
                } else {
                    holder = null;
                }
                int height = getMeasuredHeight();
                if (holder != null) {
                    bottom = holder.itemView.getBottom();
                    if (holder.itemView.getBottom() >= height) {
                        bottom = height;
                    }
                } else {
                    bottom = height;
                }
                this.paint.setColor(Theme.getColor(Theme.key_windowBackgroundGray));
                c.drawRect(0.0f, 0.0f, getMeasuredWidth(), bottom, this.paint);
                if (bottom != height) {
                    this.paint.setColor(Theme.getColor(Theme.key_windowBackgroundGray));
                    c.drawRect(0.0f, bottom, getMeasuredWidth(), height, this.paint);
                }
            }
        };
        this.listView = recyclerListView;
        recyclerListView.setClipToPadding(false);
        this.listView.setHorizontalScrollBarEnabled(false);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setItemAnimator(null);
        this.listView.setLayoutAnimation(null);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, i, z) { // from class: im.uwrkaxlmjj.ui.WallpapersListActivity.5
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f)));
        RecyclerListView recyclerListView3 = this.listView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.listAdapter = listAdapter;
        recyclerListView3.setAdapter(listAdapter);
        this.searchAdapter = new SearchAdapter(context);
        this.listView.setGlowColor(Theme.getColor(Theme.key_avatar_backgroundActionBarBlue));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$8Vz6Mvze6M4GMi10w2TAZI_El8A
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i3) {
                this.f$0.lambda$createView$3$WallpapersListActivity(view, i3);
            }
        });
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.WallpapersListActivity.6
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 1) {
                    AndroidUtilities.hideKeyboard(WallpapersListActivity.this.getParentActivity().getCurrentFocus());
                }
                WallpapersListActivity.this.scrolling = newState != 0;
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                if (WallpapersListActivity.this.listView.getAdapter() == WallpapersListActivity.this.searchAdapter) {
                    int firstVisibleItem = WallpapersListActivity.this.layoutManager.findFirstVisibleItemPosition();
                    int visibleItemCount = firstVisibleItem == -1 ? 0 : Math.abs(WallpapersListActivity.this.layoutManager.findLastVisibleItemPosition() - firstVisibleItem) + 1;
                    if (visibleItemCount > 0) {
                        int totalItemCount = WallpapersListActivity.this.layoutManager.getItemCount();
                        if (visibleItemCount != 0 && firstVisibleItem + visibleItemCount > totalItemCount - 2) {
                            WallpapersListActivity.this.searchAdapter.loadMoreResults();
                        }
                    }
                }
            }
        });
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.searchEmptyView = emptyTextProgressView;
        emptyTextProgressView.setVisibility(8);
        this.searchEmptyView.setShowAtCenter(true);
        this.searchEmptyView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.searchEmptyView.setText(LocaleController.getString("NoResult", R.string.NoResult));
        this.listView.setEmptyView(this.searchEmptyView);
        frameLayout.addView(this.searchEmptyView, LayoutHelper.createFrame(-1, -1.0f));
        updateRows();
        return this.fragmentView;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.WallpapersListActivity$2, reason: invalid class name */
    class AnonymousClass2 extends ActionBar.ActionBarMenuOnItemClick {
        AnonymousClass2() {
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public void onItemClick(int id) {
            if (id == -1) {
                if (WallpapersListActivity.this.actionBar.isActionModeShowed()) {
                    WallpapersListActivity.this.selectedWallPapers.clear();
                    WallpapersListActivity.this.actionBar.hideActionMode();
                    WallpapersListActivity.this.updateRowsSelection();
                    return;
                }
                WallpapersListActivity.this.finishFragment();
                return;
            }
            if (id == 4) {
                if (WallpapersListActivity.this.getParentActivity() == null) {
                    return;
                }
                AlertDialog.Builder builder = new AlertDialog.Builder(WallpapersListActivity.this.getParentActivity());
                builder.setMessage(LocaleController.formatString("DeleteChatBackgroundsAlert", R.string.DeleteChatBackgroundsAlert, new Object[0]));
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$2$eLz5dBDJer3GzEsuMLxV81yQNZ4
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$onItemClick$2$WallpapersListActivity$2(dialogInterface, i);
                    }
                });
                builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                WallpapersListActivity.this.showDialog(builder.create());
                return;
            }
            if (id == 3) {
                Bundle args = new Bundle();
                args.putBoolean("onlySelect", true);
                args.putInt("dialogsType", 3);
                DialogsActivity fragment = new DialogsActivity(args);
                fragment.setDelegate(new DialogsActivity.DialogsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$2$kGSgEBDlVYqWn6kyip3lG0AfgHQ
                    @Override // im.uwrkaxlmjj.ui.DialogsActivity.DialogsActivityDelegate
                    public final void didSelectDialogs(DialogsActivity dialogsActivity, ArrayList arrayList, CharSequence charSequence, boolean z) {
                        this.f$0.lambda$onItemClick$3$WallpapersListActivity$2(dialogsActivity, arrayList, charSequence, z);
                    }
                });
                WallpapersListActivity.this.presentFragment(fragment);
            }
        }

        public /* synthetic */ void lambda$onItemClick$2$WallpapersListActivity$2(DialogInterface dialogInterface, int i) {
            WallpapersListActivity.this.progressDialog = new AlertDialog(WallpapersListActivity.this.getParentActivity(), 3);
            WallpapersListActivity.this.progressDialog.setCanCancel(false);
            WallpapersListActivity.this.progressDialog.show();
            new ArrayList();
            final int[] deleteCount = {WallpapersListActivity.this.selectedWallPapers.size()};
            for (int b = 0; b < WallpapersListActivity.this.selectedWallPapers.size(); b++) {
                TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) WallpapersListActivity.this.selectedWallPapers.valueAt(b);
                TLRPC.TL_account_saveWallPaper req = new TLRPC.TL_account_saveWallPaper();
                req.settings = new TLRPC.TL_wallPaperSettings();
                req.unsave = true;
                TLRPC.TL_inputWallPaper inputWallPaper = new TLRPC.TL_inputWallPaper();
                inputWallPaper.id = wallPaper.id;
                inputWallPaper.access_hash = wallPaper.access_hash;
                req.wallpaper = inputWallPaper;
                if (wallPaper.id == WallpapersListActivity.this.selectedBackground) {
                    WallpapersListActivity.this.resetDefaultWallPaper();
                }
                ConnectionsManager.getInstance(WallpapersListActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$2$6ov4C4ZHnLB1ydR6-loQ_zn8UjU
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$null$1$WallpapersListActivity$2(deleteCount, tLObject, tL_error);
                    }
                });
            }
            WallpapersListActivity.this.selectedWallPapers.clear();
            WallpapersListActivity.this.actionBar.hideActionMode();
            WallpapersListActivity.this.actionBar.closeSearchField();
        }

        public /* synthetic */ void lambda$null$1$WallpapersListActivity$2(final int[] deleteCount, TLObject response, TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$2$FEqPrnBt0xE8A-0Z2Hmc8GoEG5g
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$WallpapersListActivity$2(deleteCount);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$WallpapersListActivity$2(int[] deleteCount) {
            deleteCount[0] = deleteCount[0] - 1;
            if (deleteCount[0] == 0) {
                WallpapersListActivity.this.loadWallpapers();
            }
        }

        public /* synthetic */ void lambda$onItemClick$3$WallpapersListActivity$2(DialogsActivity fragment1, ArrayList dids, CharSequence message, boolean param) {
            StringBuilder fmessage = new StringBuilder();
            for (int b = 0; b < WallpapersListActivity.this.selectedWallPapers.size(); b++) {
                TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) WallpapersListActivity.this.selectedWallPapers.valueAt(b);
                String link = AndroidUtilities.getWallPaperUrl(wallPaper, WallpapersListActivity.this.currentAccount);
                if (!TextUtils.isEmpty(link)) {
                    if (fmessage.length() > 0) {
                        fmessage.append('\n');
                    }
                    fmessage.append(link);
                }
            }
            WallpapersListActivity.this.selectedWallPapers.clear();
            WallpapersListActivity.this.actionBar.hideActionMode();
            WallpapersListActivity.this.actionBar.closeSearchField();
            if (dids.size() > 1 || ((Long) dids.get(0)).longValue() == UserConfig.getInstance(WallpapersListActivity.this.currentAccount).getClientUserId() || message != null) {
                WallpapersListActivity.this.updateRowsSelection();
                for (int a = 0; a < dids.size(); a++) {
                    long did = ((Long) dids.get(a)).longValue();
                    if (message != null) {
                        SendMessagesHelper.getInstance(WallpapersListActivity.this.currentAccount).sendMessage(message.toString(), did, null, null, true, null, null, null, true, 0);
                    }
                    SendMessagesHelper.getInstance(WallpapersListActivity.this.currentAccount).sendMessage(fmessage.toString(), did, null, null, true, null, null, null, true, 0);
                }
                fragment1.finishFragment();
                return;
            }
            long did2 = ((Long) dids.get(0)).longValue();
            int lower_part = (int) did2;
            int high_part = (int) (did2 >> 32);
            Bundle args1 = new Bundle();
            args1.putBoolean("scrollToTopOnResume", true);
            if (lower_part != 0) {
                if (lower_part > 0) {
                    args1.putInt("user_id", lower_part);
                } else if (lower_part < 0) {
                    args1.putInt("chat_id", -lower_part);
                }
            } else {
                args1.putInt("enc_id", high_part);
            }
            if (lower_part != 0 && !MessagesController.getInstance(WallpapersListActivity.this.currentAccount).checkCanOpenChat(args1, fragment1)) {
                return;
            }
            NotificationCenter.getInstance(WallpapersListActivity.this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
            ChatActivity chatActivity = new ChatActivity(args1);
            WallpapersListActivity.this.presentFragment(chatActivity, true);
            SendMessagesHelper.getInstance(WallpapersListActivity.this.currentAccount).sendMessage(fmessage.toString(), did2, null, null, true, null, null, null, true, 0);
        }
    }

    static /* synthetic */ boolean lambda$createView$0(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$createView$3$WallpapersListActivity(View view, int position) {
        if (getParentActivity() == null || this.listView.getAdapter() == this.searchAdapter) {
            return;
        }
        if (position == this.uploadImageRow) {
            this.updater.openGallery();
            return;
        }
        if (position == this.setColorRow) {
            WallpapersListActivity activity = new WallpapersListActivity(1);
            activity.patterns = this.patterns;
            presentFragment(activity);
        } else if (position == this.resetRow) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString("ResetChatBackgroundsAlertTitle", R.string.ResetChatBackgroundsAlertTitle));
            builder.setMessage(LocaleController.getString("ResetChatBackgroundsAlert", R.string.ResetChatBackgroundsAlert));
            builder.setPositiveButton(LocaleController.getString("Reset", R.string.Reset), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$R2k4-235sigbYmPB-gk23zp9kes
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$2$WallpapersListActivity(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            AlertDialog dialog = builder.create();
            showDialog(dialog);
            TextView button = (TextView) dialog.getButton(-1);
            if (button != null) {
                button.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
            }
        }
    }

    public /* synthetic */ void lambda$null$2$WallpapersListActivity(DialogInterface dialogInterface, int i) {
        if (this.actionBar.isActionModeShowed()) {
            this.selectedWallPapers.clear();
            this.actionBar.hideActionMode();
            updateRowsSelection();
        }
        AlertDialog alertDialog = new AlertDialog(getParentActivity(), 3);
        this.progressDialog = alertDialog;
        alertDialog.setCanCancel(false);
        this.progressDialog.show();
        TLRPC.TL_account_resetWallPapers req = new TLRPC.TL_account_resetWallPapers();
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$OkgRW6Nj4SheNu7kvyXURUrVUaI
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$1$WallpapersListActivity(tLObject, tL_error);
            }
        });
        resetDefaultWallPaper();
        fillWallpapersWithCustom();
    }

    public /* synthetic */ void lambda$null$1$WallpapersListActivity(TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$ggl7oKKLuBQ0MC_Bd-X5v2Dt9ZU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.loadWallpapers();
            }
        });
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        this.selectedBackground = Theme.getSelectedBackgroundId();
        this.selectedPattern = preferences.getLong("selectedPattern", 0L);
        this.selectedColor = preferences.getInt("selectedColor", 0);
        this.selectedIntensity = preferences.getFloat("selectedIntensity", 1.0f);
        this.selectedBackgroundMotion = preferences.getBoolean("selectedBackgroundMotion", false);
        this.selectedBackgroundBlurred = preferences.getBoolean("selectedBackgroundBlurred", false);
        fillWallpapersWithCustom();
        fixLayout();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        fixLayout();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        this.updater.onActivityResult(requestCode, resultCode, data);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void saveSelfArgs(Bundle args) {
        String currentPicturePath = this.updater.getCurrentPicturePath();
        if (currentPicturePath != null) {
            args.putString("path", currentPicturePath);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void restoreSelfArgs(Bundle args) {
        this.updater.setCurrentPicturePath(args.getString("path"));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean onItemLongClick(WallpaperCell view, Object object, int index) {
        if (this.actionBar.isActionModeShowed() || getParentActivity() == null || !(object instanceof TLRPC.TL_wallPaper)) {
            return false;
        }
        TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) object;
        AndroidUtilities.hideKeyboard(getParentActivity().getCurrentFocus());
        this.selectedWallPapers.put(wallPaper.id, wallPaper);
        this.selectedMessagesCountTextView.setNumber(1, false);
        AnimatorSet animatorSet = new AnimatorSet();
        ArrayList<Animator> animators = new ArrayList<>();
        for (int i = 0; i < this.actionModeViews.size(); i++) {
            View view2 = this.actionModeViews.get(i);
            AndroidUtilities.clearDrawableAnimation(view2);
            animators.add(ObjectAnimator.ofFloat(view2, (Property<View, Float>) View.SCALE_Y, 0.1f, 1.0f));
        }
        animatorSet.playTogether(animators);
        animatorSet.setDuration(250L);
        animatorSet.start();
        this.scrolling = false;
        this.actionBar.showActionMode();
        view.setChecked(index, true, true);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onItemClick(WallpaperCell view, Object object, int index) {
        Object object2 = object;
        if (!this.actionBar.isActionModeShowed()) {
            long id = getWallPaperId(object2);
            if (object2 instanceof TLRPC.TL_wallPaper) {
                TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) object2;
                if (wallPaper.pattern) {
                    object2 = new ColorWallpaper(wallPaper.id, wallPaper.settings.background_color, wallPaper.id, wallPaper.settings.intensity / 100.0f, wallPaper.settings.motion, null);
                }
            }
            WallpaperActivity wallpaperActivity = new WallpaperActivity(object2, null);
            if (this.currentType == 1) {
                wallpaperActivity.setDelegate(new WallpaperActivity.WallpaperActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$F_MWPF0in8tQCPVYlrsmyyBJpmc
                    @Override // im.uwrkaxlmjj.ui.WallpaperActivity.WallpaperActivityDelegate
                    public final void didSetNewBackground() {
                        this.f$0.removeSelfFromStack();
                    }
                });
            }
            if (this.selectedBackground == id) {
                wallpaperActivity.setInitialModes(this.selectedBackgroundBlurred, this.selectedBackgroundMotion);
            }
            wallpaperActivity.setPatterns(this.patterns);
            presentFragment(wallpaperActivity);
            return;
        }
        if (!(object2 instanceof TLRPC.TL_wallPaper)) {
            return;
        }
        TLRPC.TL_wallPaper wallPaper2 = (TLRPC.TL_wallPaper) object2;
        if (this.selectedWallPapers.indexOfKey(wallPaper2.id) >= 0) {
            this.selectedWallPapers.remove(wallPaper2.id);
        } else {
            this.selectedWallPapers.put(wallPaper2.id, wallPaper2);
        }
        if (this.selectedWallPapers.size() != 0) {
            this.selectedMessagesCountTextView.setNumber(this.selectedWallPapers.size(), true);
        } else {
            this.actionBar.hideActionMode();
        }
        this.scrolling = false;
        view.setChecked(index, this.selectedWallPapers.indexOfKey(wallPaper2.id) >= 0, true);
    }

    private long getWallPaperId(Object object) {
        if (object instanceof TLRPC.TL_wallPaper) {
            return ((TLRPC.TL_wallPaper) object).id;
        }
        if (object instanceof ColorWallpaper) {
            return ((ColorWallpaper) object).id;
        }
        if (object instanceof FileWallpaper) {
            return ((FileWallpaper) object).id;
        }
        return 0L;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateRowsSelection() {
        int count = this.listView.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = this.listView.getChildAt(a);
            if (child instanceof WallpaperCell) {
                WallpaperCell cell = (WallpaperCell) child;
                for (int b = 0; b < 5; b++) {
                    cell.setChecked(b, false, true);
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id != NotificationCenter.wallpapersDidLoad) {
            if (id == NotificationCenter.didSetNewWallpapper) {
                RecyclerListView recyclerListView = this.listView;
                if (recyclerListView != null) {
                    recyclerListView.invalidateViews();
                }
                if (this.actionBar != null) {
                    this.actionBar.closeSearchField();
                    return;
                }
                return;
            }
            if (id == NotificationCenter.wallpapersNeedReload) {
                MessagesStorage.getInstance(this.currentAccount).getWallpapers();
                return;
            }
            return;
        }
        ArrayList<TLRPC.TL_wallPaper> arrayList = (ArrayList) args[0];
        this.patterns.clear();
        if (this.currentType != 1) {
            this.wallPapers.clear();
            this.allWallPapers.clear();
            this.allWallPapersDict.clear();
            this.allWallPapers.addAll(arrayList);
        }
        int N = arrayList.size();
        for (int a = 0; a < N; a++) {
            TLRPC.TL_wallPaper wallPaper = arrayList.get(a);
            if (wallPaper.pattern) {
                this.patterns.add(wallPaper);
            }
            if (this.currentType != 1 && (!wallPaper.pattern || wallPaper.settings != null)) {
                this.allWallPapersDict.put(wallPaper.id, wallPaper);
                this.wallPapers.add(wallPaper);
            }
        }
        this.selectedBackground = Theme.getSelectedBackgroundId();
        fillWallpapersWithCustom();
        loadWallpapers();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void loadWallpapers() {
        long acc = 0;
        int N = this.allWallPapers.size();
        for (int a = 0; a < N; a++) {
            Object object = this.allWallPapers.get(a);
            if (object instanceof TLRPC.TL_wallPaper) {
                TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) object;
                int high_id = (int) (wallPaper.id >> 32);
                int lower_id = (int) wallPaper.id;
                acc = (((((((acc * 20261) + 2147483648L) + ((long) high_id)) % 2147483648L) * 20261) + 2147483648L) + ((long) lower_id)) % 2147483648L;
            }
        }
        TLRPC.TL_account_getWallPapers req = new TLRPC.TL_account_getWallPapers();
        req.hash = (int) acc;
        int reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$YtKVvJRc8FJkLfCVfSY6BTyoozw
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadWallpapers$5$WallpapersListActivity(tLObject, tL_error);
            }
        });
        ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(reqId, this.classGuid);
    }

    public /* synthetic */ void lambda$loadWallpapers$5$WallpapersListActivity(final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$7840o0uuQpZX8ja2pEetad96FFU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$4$WallpapersListActivity(response);
            }
        });
    }

    public /* synthetic */ void lambda$null$4$WallpapersListActivity(TLObject response) {
        if (response instanceof TLRPC.TL_account_wallPapers) {
            TLRPC.TL_account_wallPapers res = (TLRPC.TL_account_wallPapers) response;
            this.patterns.clear();
            if (this.currentType != 1) {
                this.wallPapers.clear();
                this.allWallPapersDict.clear();
                this.allWallPapers.clear();
                this.allWallPapers.addAll(res.wallpapers);
            }
            int N = res.wallpapers.size();
            for (int a = 0; a < N; a++) {
                TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) res.wallpapers.get(a);
                this.allWallPapersDict.put(wallPaper.id, wallPaper);
                if (wallPaper.pattern) {
                    this.patterns.add(wallPaper);
                }
                if (this.currentType != 1 && (!wallPaper.pattern || wallPaper.settings != null)) {
                    this.wallPapers.add(wallPaper);
                }
            }
            fillWallpapersWithCustom();
            MessagesStorage.getInstance(this.currentAccount).putWallpapers(res.wallpapers, 1);
        }
        AlertDialog alertDialog = this.progressDialog;
        if (alertDialog != null) {
            alertDialog.dismiss();
            this.listView.smoothScrollToPosition(0);
        }
    }

    private void fillWallpapersWithCustom() {
        if (this.currentType != 0) {
            return;
        }
        MessagesController.getGlobalMainSettings();
        ColorWallpaper colorWallpaper = this.addedColorWallpaper;
        if (colorWallpaper != null) {
            this.wallPapers.remove(colorWallpaper);
            this.addedColorWallpaper = null;
        }
        FileWallpaper fileWallpaper = this.addedFileWallpaper;
        if (fileWallpaper != null) {
            this.wallPapers.remove(fileWallpaper);
            this.addedFileWallpaper = null;
        }
        FileWallpaper fileWallpaper2 = this.catsWallpaper;
        if (fileWallpaper2 == null) {
            this.catsWallpaper = new FileWallpaper(Theme.DEFAULT_BACKGROUND_ID, R.drawable.background_hd, R.drawable.catstile);
        } else {
            this.wallPapers.remove(fileWallpaper2);
        }
        FileWallpaper fileWallpaper3 = this.themeWallpaper;
        if (fileWallpaper3 != null) {
            this.wallPapers.remove(fileWallpaper3);
        }
        final boolean currentThemeDark = Theme.getCurrentTheme().isDark();
        Collections.sort(this.wallPapers, new Comparator() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$Pg9XQCZvXWwQXNmsn2ABEhvCzps
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return this.f$0.lambda$fillWallpapersWithCustom$6$WallpapersListActivity(currentThemeDark, obj, obj2);
            }
        });
        if (Theme.hasWallpaperFromTheme() && !Theme.isThemeWallpaperPublic()) {
            if (this.themeWallpaper == null) {
                this.themeWallpaper = new FileWallpaper(-2L, -2, -2);
            }
            this.wallPapers.add(0, this.themeWallpaper);
        } else {
            this.themeWallpaper = null;
        }
        long j = this.selectedBackground;
        if (j == -1 || (j != Theme.DEFAULT_BACKGROUND_ID && ((j < -100 || j > 0) && this.allWallPapersDict.indexOfKey(this.selectedBackground) < 0))) {
            long j2 = this.selectedPattern;
            if (j2 != 0) {
                ColorWallpaper colorWallpaper2 = new ColorWallpaper(this.selectedBackground, this.selectedColor, j2, this.selectedIntensity, this.selectedBackgroundMotion, new File(ApplicationLoader.getFilesDirFixed(), "wallpaper.jpg"));
                this.addedColorWallpaper = colorWallpaper2;
                this.wallPapers.add(0, colorWallpaper2);
            } else {
                int i = this.selectedColor;
                if (i != 0) {
                    ColorWallpaper colorWallpaper3 = new ColorWallpaper(this.selectedBackground, i);
                    this.addedColorWallpaper = colorWallpaper3;
                    this.wallPapers.add(0, colorWallpaper3);
                } else {
                    FileWallpaper fileWallpaper4 = new FileWallpaper(this.selectedBackground, new File(ApplicationLoader.getFilesDirFixed(), "wallpaper.jpg"), new File(ApplicationLoader.getFilesDirFixed(), this.selectedBackgroundBlurred ? "wallpaper_original.jpg" : "wallpaper.jpg"));
                    this.addedFileWallpaper = fileWallpaper4;
                    this.wallPapers.add(0, fileWallpaper4);
                }
            }
        } else {
            int i2 = this.selectedColor;
            if (i2 != 0) {
                long j3 = this.selectedBackground;
                if (j3 >= -100 && this.selectedPattern < -1) {
                    ColorWallpaper colorWallpaper4 = new ColorWallpaper(j3, i2);
                    this.addedColorWallpaper = colorWallpaper4;
                    this.wallPapers.add(0, colorWallpaper4);
                }
            }
        }
        if (this.selectedBackground == Theme.DEFAULT_BACKGROUND_ID) {
            this.wallPapers.add(0, this.catsWallpaper);
        } else {
            this.wallPapers.add(this.catsWallpaper);
        }
        updateRows();
    }

    public /* synthetic */ int lambda$fillWallpapersWithCustom$6$WallpapersListActivity(boolean currentThemeDark, Object o1, Object o2) {
        if (!(o1 instanceof TLRPC.TL_wallPaper) || !(o2 instanceof TLRPC.TL_wallPaper)) {
            return 0;
        }
        TLRPC.TL_wallPaper wallPaper1 = (TLRPC.TL_wallPaper) o1;
        TLRPC.TL_wallPaper wallPaper2 = (TLRPC.TL_wallPaper) o2;
        if (wallPaper1.id == this.selectedBackground) {
            return -1;
        }
        if (wallPaper2.id == this.selectedBackground) {
            return 1;
        }
        int index1 = this.allWallPapers.indexOf(wallPaper1);
        int index2 = this.allWallPapers.indexOf(wallPaper2);
        if (!(wallPaper1.dark && wallPaper2.dark) && (wallPaper1.dark || wallPaper2.dark)) {
            return (!wallPaper1.dark || wallPaper2.dark) ? currentThemeDark ? 1 : -1 : currentThemeDark ? -1 : 1;
        }
        if (index1 > index2) {
            return 1;
        }
        return index1 < index2 ? -1 : 0;
    }

    private void updateRows() {
        this.rowCount = 0;
        if (this.currentType == 0) {
            int i = 0 + 1;
            this.rowCount = i;
            this.uploadImageRow = 0;
            int i2 = i + 1;
            this.rowCount = i2;
            this.setColorRow = i;
            this.rowCount = i2 + 1;
            this.sectionRow = i2;
        } else {
            this.uploadImageRow = -1;
            this.setColorRow = -1;
            this.sectionRow = -1;
        }
        if (!this.wallPapers.isEmpty()) {
            int iCeil = (int) Math.ceil(this.wallPapers.size() / this.columnsCount);
            this.totalWallpaperRows = iCeil;
            int i3 = this.rowCount;
            this.wallPaperStartRow = i3;
            this.rowCount = i3 + iCeil;
        } else {
            this.wallPaperStartRow = -1;
        }
        if (this.currentType == 0) {
            int i4 = this.rowCount;
            int i5 = i4 + 1;
            this.rowCount = i5;
            this.resetSectionRow = i4;
            int i6 = i5 + 1;
            this.rowCount = i6;
            this.resetRow = i5;
            this.rowCount = i6 + 1;
            this.resetInfoRow = i6;
        } else {
            this.resetSectionRow = -1;
            this.resetRow = -1;
            this.resetInfoRow = -1;
        }
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            this.scrolling = true;
            listAdapter.notifyDataSetChanged();
        }
    }

    private void fixLayout() {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            ViewTreeObserver obs = recyclerListView.getViewTreeObserver();
            obs.addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() { // from class: im.uwrkaxlmjj.ui.WallpapersListActivity.7
                @Override // android.view.ViewTreeObserver.OnPreDrawListener
                public boolean onPreDraw() {
                    WallpapersListActivity.this.fixLayoutInternal();
                    if (WallpapersListActivity.this.listView != null) {
                        WallpapersListActivity.this.listView.getViewTreeObserver().removeOnPreDrawListener(this);
                        return true;
                    }
                    return true;
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void fixLayoutInternal() {
        if (getParentActivity() == null) {
            return;
        }
        WindowManager manager = (WindowManager) ApplicationLoader.applicationContext.getSystemService("window");
        int rotation = manager.getDefaultDisplay().getRotation();
        if (AndroidUtilities.isTablet()) {
            this.columnsCount = 3;
        } else if (rotation == 3 || rotation == 1) {
            this.columnsCount = 5;
        } else {
            this.columnsCount = 3;
        }
        updateRows();
    }

    private class ColorCell extends View {
        private int color;

        public ColorCell(Context context) {
            super(context);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            setMeasuredDimension(AndroidUtilities.dp(50.0f), AndroidUtilities.dp(62.0f));
        }

        public void setColor(int value) {
            this.color = value;
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            WallpapersListActivity.this.colorPaint.setColor(this.color);
            canvas.drawCircle(AndroidUtilities.dp(25.0f), AndroidUtilities.dp(31.0f), AndroidUtilities.dp(18.0f), WallpapersListActivity.this.colorPaint);
            if (this.color == Theme.getColor(Theme.key_windowBackgroundWhite)) {
                canvas.drawCircle(AndroidUtilities.dp(25.0f), AndroidUtilities.dp(31.0f), AndroidUtilities.dp(18.0f), WallpapersListActivity.this.colorFramePaint);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class SearchAdapter extends RecyclerListView.SelectionAdapter {
        private int imageReqId;
        private RecyclerListView innerListView;
        private String lastSearchImageString;
        private String lastSearchString;
        private int lastSearchToken;
        private Context mContext;
        private String nextImagesSearchOffset;
        private Runnable searchRunnable;
        private boolean searchingUser;
        private String selectedColor;
        private ArrayList<MediaController.SearchImage> searchResult = new ArrayList<>();
        private HashMap<String, MediaController.SearchImage> searchResultKeys = new HashMap<>();
        private boolean bingSearchEndReached = true;

        private class CategoryAdapterRecycler extends RecyclerListView.SelectionAdapter {
            private CategoryAdapterRecycler() {
            }

            @Override // androidx.recyclerview.widget.RecyclerView.Adapter
            public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
                View view = WallpapersListActivity.this.new ColorCell(SearchAdapter.this.mContext);
                return new RecyclerListView.Holder(view);
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
            public boolean isEnabled(RecyclerView.ViewHolder holder) {
                return true;
            }

            @Override // androidx.recyclerview.widget.RecyclerView.Adapter
            public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
                ColorCell cell = (ColorCell) holder.itemView;
                cell.setColor(WallpapersListActivity.searchColors[position]);
            }

            @Override // androidx.recyclerview.widget.RecyclerView.Adapter
            public int getItemCount() {
                return WallpapersListActivity.searchColors.length;
            }
        }

        public SearchAdapter(Context context) {
            this.mContext = context;
        }

        public RecyclerListView getInnerListView() {
            return this.innerListView;
        }

        public void onDestroy() {
            if (this.imageReqId != 0) {
                ConnectionsManager.getInstance(WallpapersListActivity.this.currentAccount).cancelRequest(this.imageReqId, true);
                this.imageReqId = 0;
            }
        }

        public void clearColor() {
            this.selectedColor = null;
            processSearch(null, true);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void processSearch(String text, boolean now) {
            if (text != null && this.selectedColor != null) {
                text = "#color" + this.selectedColor + " " + text;
            }
            Runnable runnable = this.searchRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
                this.searchRunnable = null;
            }
            if (!TextUtils.isEmpty(text)) {
                WallpapersListActivity.this.searchEmptyView.showProgress();
                final String textFinal = text;
                if (now) {
                    doSearch(textFinal);
                } else {
                    Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$SearchAdapter$X3ldNFng8mGY0VAe9TREQLZVBqk
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$processSearch$0$WallpapersListActivity$SearchAdapter(textFinal);
                        }
                    };
                    this.searchRunnable = runnable2;
                    AndroidUtilities.runOnUIThread(runnable2, 500L);
                }
            } else {
                this.searchResult.clear();
                this.searchResultKeys.clear();
                this.bingSearchEndReached = true;
                this.lastSearchString = null;
                if (this.imageReqId != 0) {
                    ConnectionsManager.getInstance(WallpapersListActivity.this.currentAccount).cancelRequest(this.imageReqId, true);
                    this.imageReqId = 0;
                }
                WallpapersListActivity.this.searchEmptyView.showTextView();
            }
            notifyDataSetChanged();
        }

        public /* synthetic */ void lambda$processSearch$0$WallpapersListActivity$SearchAdapter(String textFinal) {
            doSearch(textFinal);
            this.searchRunnable = null;
        }

        private void doSearch(String textFinal) {
            this.searchResult.clear();
            this.searchResultKeys.clear();
            this.bingSearchEndReached = true;
            searchImages(textFinal, "", true);
            this.lastSearchString = textFinal;
            notifyDataSetChanged();
        }

        private void searchBotUser() {
            if (this.searchingUser) {
                return;
            }
            this.searchingUser = true;
            TLRPC.TL_contacts_resolveUsername req = new TLRPC.TL_contacts_resolveUsername();
            req.username = MessagesController.getInstance(WallpapersListActivity.this.currentAccount).imageSearchBot;
            ConnectionsManager.getInstance(WallpapersListActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$SearchAdapter$Xl40dlvj4ZLe7J1a7akYVGIQOmU
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$searchBotUser$2$WallpapersListActivity$SearchAdapter(tLObject, tL_error);
                }
            });
        }

        public /* synthetic */ void lambda$searchBotUser$2$WallpapersListActivity$SearchAdapter(final TLObject response, TLRPC.TL_error error) {
            if (response != null) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$SearchAdapter$zX7dnAKux5pc5nyXG4PZrifeM4A
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$1$WallpapersListActivity$SearchAdapter(response);
                    }
                });
            } else if (error != null) {
                cancelSearchingUser();
            }
        }

        public /* synthetic */ void lambda$null$1$WallpapersListActivity$SearchAdapter(TLObject response) {
            TLRPC.TL_contacts_resolvedPeer res = (TLRPC.TL_contacts_resolvedPeer) response;
            MessagesController.getInstance(WallpapersListActivity.this.currentAccount).putUsers(res.users, false);
            MessagesController.getInstance(WallpapersListActivity.this.currentAccount).putChats(res.chats, false);
            MessagesStorage.getInstance(WallpapersListActivity.this.currentAccount).putUsersAndChats(res.users, res.chats, true, true);
            String str = this.lastSearchImageString;
            this.lastSearchImageString = null;
            searchImages(str, "", false);
        }

        public void loadMoreResults() {
            if (this.bingSearchEndReached || this.imageReqId != 0) {
                return;
            }
            searchImages(this.lastSearchString, this.nextImagesSearchOffset, true);
        }

        private void searchImages(String query, String offset, boolean searchUser) {
            if (this.imageReqId != 0) {
                ConnectionsManager.getInstance(WallpapersListActivity.this.currentAccount).cancelRequest(this.imageReqId, true);
                this.imageReqId = 0;
            }
            this.lastSearchImageString = query;
            TLObject object = MessagesController.getInstance(WallpapersListActivity.this.currentAccount).getUserOrChat(MessagesController.getInstance(WallpapersListActivity.this.currentAccount).imageSearchBot);
            if (!(object instanceof TLRPC.User)) {
                if (searchUser) {
                    searchBotUser();
                    return;
                }
                return;
            }
            TLRPC.User user = (TLRPC.User) object;
            TLRPC.TL_messages_getInlineBotResults req = new TLRPC.TL_messages_getInlineBotResults();
            req.query = "#wallpaper " + query;
            req.bot = MessagesController.getInstance(WallpapersListActivity.this.currentAccount).getInputUser(user);
            req.offset = offset;
            req.peer = new TLRPC.TL_inputPeerEmpty();
            final int token = this.lastSearchToken + 1;
            this.lastSearchToken = token;
            this.imageReqId = ConnectionsManager.getInstance(WallpapersListActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$SearchAdapter$wri1wSrZ9AfmxoKtLaSaA4DKPWE
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$searchImages$4$WallpapersListActivity$SearchAdapter(token, tLObject, tL_error);
                }
            });
            ConnectionsManager.getInstance(WallpapersListActivity.this.currentAccount).bindRequestToGuid(this.imageReqId, WallpapersListActivity.this.classGuid);
        }

        public /* synthetic */ void lambda$searchImages$4$WallpapersListActivity$SearchAdapter(final int token, final TLObject response, TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$SearchAdapter$__rVnIIdt5IE7TvkGcETJDzbnTQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$3$WallpapersListActivity$SearchAdapter(token, response);
                }
            });
        }

        public /* synthetic */ void lambda$null$3$WallpapersListActivity$SearchAdapter(int token, TLObject response) {
            if (token != this.lastSearchToken) {
                return;
            }
            this.imageReqId = 0;
            int oldCount = this.searchResult.size();
            if (response != null) {
                TLRPC.messages_BotResults res = (TLRPC.messages_BotResults) response;
                this.nextImagesSearchOffset = res.next_offset;
                int count = res.results.size();
                for (int a = 0; a < count; a++) {
                    TLRPC.BotInlineResult result = res.results.get(a);
                    if ("photo".equals(result.type) && !this.searchResultKeys.containsKey(result.id)) {
                        MediaController.SearchImage bingImage = new MediaController.SearchImage();
                        if (result.photo != null) {
                            TLRPC.PhotoSize size = FileLoader.getClosestPhotoSizeWithSize(result.photo.sizes, AndroidUtilities.getPhotoSize());
                            TLRPC.PhotoSize size2 = FileLoader.getClosestPhotoSizeWithSize(result.photo.sizes, 320);
                            if (size != null) {
                                bingImage.width = size.w;
                                bingImage.height = size.h;
                                bingImage.photoSize = size;
                                bingImage.photo = result.photo;
                                bingImage.size = size.size;
                                bingImage.thumbPhotoSize = size2;
                                bingImage.id = result.id;
                                bingImage.type = 0;
                                this.searchResult.add(bingImage);
                                this.searchResultKeys.put(bingImage.id, bingImage);
                            }
                        } else if (result.content != null) {
                            int b = 0;
                            while (true) {
                                if (b >= result.content.attributes.size()) {
                                    break;
                                }
                                TLRPC.DocumentAttribute attribute = result.content.attributes.get(b);
                                if (!(attribute instanceof TLRPC.TL_documentAttributeImageSize)) {
                                    b++;
                                } else {
                                    bingImage.width = attribute.w;
                                    bingImage.height = attribute.h;
                                    break;
                                }
                            }
                            if (result.thumb != null) {
                                bingImage.thumbUrl = result.thumb.url;
                            } else {
                                bingImage.thumbUrl = null;
                            }
                            bingImage.imageUrl = result.content.url;
                            bingImage.size = result.content.size;
                            bingImage.id = result.id;
                            bingImage.type = 0;
                            this.searchResult.add(bingImage);
                            this.searchResultKeys.put(bingImage.id, bingImage);
                        }
                    }
                }
                this.bingSearchEndReached = oldCount == this.searchResult.size() || this.nextImagesSearchOffset == null;
            }
            if (oldCount != this.searchResult.size()) {
                int prevLastRow = oldCount % WallpapersListActivity.this.columnsCount;
                int oldRowCount = (int) Math.ceil(oldCount / WallpapersListActivity.this.columnsCount);
                if (prevLastRow != 0) {
                    notifyItemChanged(((int) Math.ceil(oldCount / WallpapersListActivity.this.columnsCount)) - 1);
                }
                int newRowCount = (int) Math.ceil(this.searchResult.size() / WallpapersListActivity.this.columnsCount);
                WallpapersListActivity.this.searchAdapter.notifyItemRangeInserted(oldRowCount, newRowCount - oldRowCount);
            }
            WallpapersListActivity.this.searchEmptyView.showTextView();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void cancelSearchingUser() {
            if (WallpapersListActivity.this.searchAdapter.imageReqId != 0) {
                ConnectionsManager.getInstance(WallpapersListActivity.this.currentAccount).cancelRequest(WallpapersListActivity.this.searchAdapter.imageReqId, true);
                WallpapersListActivity.this.searchAdapter.imageReqId = 0;
            }
            WallpapersListActivity.this.searchAdapter.searchingUser = false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (!TextUtils.isEmpty(this.lastSearchString)) {
                return (int) Math.ceil(this.searchResult.size() / WallpapersListActivity.this.columnsCount);
            }
            return 2;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() != 2;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType != 0) {
                if (viewType == 1) {
                    RecyclerListView horizontalListView = new RecyclerListView(this.mContext) { // from class: im.uwrkaxlmjj.ui.WallpapersListActivity.SearchAdapter.2
                        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
                        public boolean onInterceptTouchEvent(MotionEvent e) {
                            if (getParent() != null && getParent().getParent() != null) {
                                getParent().getParent().requestDisallowInterceptTouchEvent(true);
                            }
                            return super.onInterceptTouchEvent(e);
                        }
                    };
                    horizontalListView.setItemAnimator(null);
                    horizontalListView.setLayoutAnimation(null);
                    LinearLayoutManager layoutManager = new LinearLayoutManager(this.mContext) { // from class: im.uwrkaxlmjj.ui.WallpapersListActivity.SearchAdapter.3
                        @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
                        public boolean supportsPredictiveItemAnimations() {
                            return false;
                        }
                    };
                    horizontalListView.setPadding(AndroidUtilities.dp(7.0f), 0, AndroidUtilities.dp(7.0f), 0);
                    horizontalListView.setClipToPadding(false);
                    layoutManager.setOrientation(0);
                    horizontalListView.setLayoutManager(layoutManager);
                    horizontalListView.setAdapter(new CategoryAdapterRecycler());
                    horizontalListView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$WallpapersListActivity$SearchAdapter$6rQ-SToWc6CegavsiXBZ51DGg6o
                        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                        public final void onItemClick(View view2, int i) {
                            this.f$0.lambda$onCreateViewHolder$5$WallpapersListActivity$SearchAdapter(view2, i);
                        }
                    });
                    view = horizontalListView;
                    this.innerListView = horizontalListView;
                } else if (viewType == 2) {
                    view = new GraySectionCell(this.mContext);
                }
            } else {
                view = new WallpaperCell(this.mContext) { // from class: im.uwrkaxlmjj.ui.WallpapersListActivity.SearchAdapter.1
                    @Override // im.uwrkaxlmjj.ui.cells.WallpaperCell
                    protected void onWallpaperClick(Object wallPaper, int index) {
                        WallpapersListActivity.this.presentFragment(new WallpaperActivity(wallPaper, null));
                    }
                };
            }
            if (viewType == 1) {
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(60.0f)));
            } else {
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            }
            return new RecyclerListView.Holder(view);
        }

        public /* synthetic */ void lambda$onCreateViewHolder$5$WallpapersListActivity$SearchAdapter(View view1, int position) {
            String color = LocaleController.getString("BackgroundSearchColor", R.string.BackgroundSearchColor);
            Spannable spannable = new SpannableString(color + " " + LocaleController.getString(WallpapersListActivity.searchColorsNames[position], WallpapersListActivity.searchColorsNamesR[position]));
            spannable.setSpan(new ForegroundColorSpan(Theme.getColor(Theme.key_actionBarDefaultSubtitle)), color.length(), spannable.length(), 33);
            WallpapersListActivity.this.searchItem.setSearchFieldCaption(spannable);
            WallpapersListActivity.this.searchItem.setSearchFieldHint(null);
            WallpapersListActivity.this.searchItem.setSearchFieldText("", true);
            this.selectedColor = WallpapersListActivity.searchColorsNames[position];
            processSearch("", true);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType == 2) {
                    GraySectionCell cell = (GraySectionCell) holder.itemView;
                    cell.setText(LocaleController.getString("SearchByColor", R.string.SearchByColor));
                    return;
                }
                return;
            }
            WallpaperCell wallpaperCell = (WallpaperCell) holder.itemView;
            int position2 = position * WallpapersListActivity.this.columnsCount;
            int totalRows = (int) Math.ceil(this.searchResult.size() / WallpapersListActivity.this.columnsCount);
            wallpaperCell.setParams(WallpapersListActivity.this.columnsCount, position2 == 0, position2 / WallpapersListActivity.this.columnsCount == totalRows + (-1));
            for (int a = 0; a < WallpapersListActivity.this.columnsCount; a++) {
                int p = position2 + a;
                Object wallPaper = p < this.searchResult.size() ? this.searchResult.get(p) : null;
                wallpaperCell.setWallpaper(WallpapersListActivity.this.currentType, a, wallPaper, 0L, null, false);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (TextUtils.isEmpty(this.lastSearchString)) {
                if (position == 0) {
                    return 2;
                }
                return 1;
            }
            return 0;
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() == 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return WallpapersListActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new TextCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 1) {
                view = new ShadowSectionCell(this.mContext);
                view.setBackgroundColor(0);
            } else if (viewType == 3) {
                view = new TextInfoPrivacyCell(this.mContext);
            } else {
                view = new WallpaperCell(this.mContext) { // from class: im.uwrkaxlmjj.ui.WallpapersListActivity.ListAdapter.1
                    @Override // im.uwrkaxlmjj.ui.cells.WallpaperCell
                    protected void onWallpaperClick(Object wallPaper, int index) {
                        WallpapersListActivity.this.onItemClick(this, wallPaper, index);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.WallpaperCell
                    protected boolean onWallpaperLongClick(Object wallPaper, int index) {
                        return WallpapersListActivity.this.onItemLongClick(this, wallPaper, index);
                    }
                };
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            long id;
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                TextCell textCell = (TextCell) holder.itemView;
                if (position != WallpapersListActivity.this.uploadImageRow) {
                    if (position != WallpapersListActivity.this.setColorRow) {
                        if (position == WallpapersListActivity.this.resetRow) {
                            textCell.setText(LocaleController.getString("ResetChatBackgrounds", R.string.ResetChatBackgrounds), false);
                            textCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                            return;
                        }
                        return;
                    }
                    textCell.setTextAndIcon(LocaleController.getString("SetColor", R.string.SetColor), R.drawable.menu_palette, false);
                    return;
                }
                textCell.setTextAndIcon(LocaleController.getString("SelectFromGallery", R.string.SelectFromGallery), R.drawable.profile_photos, true);
                textCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                return;
            }
            if (itemViewType != 2) {
                if (itemViewType == 3) {
                    TextInfoPrivacyCell cell = (TextInfoPrivacyCell) holder.itemView;
                    if (position == WallpapersListActivity.this.resetInfoRow) {
                        cell.setText(LocaleController.getString("ResetChatBackgroundsInfo", R.string.ResetChatBackgroundsInfo));
                        return;
                    }
                    return;
                }
                return;
            }
            WallpaperCell wallpaperCell = (WallpaperCell) holder.itemView;
            int position2 = (position - WallpapersListActivity.this.wallPaperStartRow) * WallpapersListActivity.this.columnsCount;
            wallpaperCell.setParams(WallpapersListActivity.this.columnsCount, position2 == 0, position2 / WallpapersListActivity.this.columnsCount == WallpapersListActivity.this.totalWallpaperRows - 1);
            for (int a = 0; a < WallpapersListActivity.this.columnsCount; a++) {
                int p = position2 + a;
                Object wallPaper = p < WallpapersListActivity.this.wallPapers.size() ? WallpapersListActivity.this.wallPapers.get(p) : null;
                wallpaperCell.setWallpaper(WallpapersListActivity.this.currentType, a, wallPaper, WallpapersListActivity.this.selectedBackground, null, false);
                if (wallPaper instanceof TLRPC.TL_wallPaper) {
                    TLRPC.TL_wallPaper object = (TLRPC.TL_wallPaper) wallPaper;
                    id = object.id;
                } else {
                    id = 0;
                }
                if (WallpapersListActivity.this.actionBar.isActionModeShowed()) {
                    wallpaperCell.setChecked(a, WallpapersListActivity.this.selectedWallPapers.indexOfKey(id) >= 0, !WallpapersListActivity.this.scrolling);
                } else {
                    wallpaperCell.setChecked(a, false, !WallpapersListActivity.this.scrolling);
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != WallpapersListActivity.this.uploadImageRow && position != WallpapersListActivity.this.setColorRow && position != WallpapersListActivity.this.resetRow) {
                if (position != WallpapersListActivity.this.sectionRow && position != WallpapersListActivity.this.resetSectionRow) {
                    if (position == WallpapersListActivity.this.resetInfoRow) {
                        return 3;
                    }
                    return 2;
                }
                return 1;
            }
            return 0;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resetDefaultWallPaper() {
        this.selectedBackground = Theme.DEFAULT_BACKGROUND_ID;
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        SharedPreferences.Editor editor = preferences.edit();
        editor.putLong("selectedBackground2", this.selectedBackground);
        editor.remove("selectedBackgroundSlug");
        editor.putBoolean("selectedBackgroundBlurred", false);
        editor.putBoolean("selectedBackgroundMotion", false);
        editor.putInt("selectedColor", 0);
        editor.putFloat("selectedIntensity", 1.0f);
        editor.putLong("selectedPattern", 0L);
        editor.putBoolean("overrideThemeWallpaper", true);
        editor.commit();
        Theme.reloadWallpaper();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, 0, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, 0, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.listView, 0, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, 0, new Class[]{TextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.listView, 0, new Class[]{GraySectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_graySectionText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{GraySectionCell.class}, null, null, null, Theme.key_graySection), new ThemeDescription(this.searchEmptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_emptyListPlaceholder), new ThemeDescription(this.searchEmptyView, ThemeDescription.FLAG_PROGRESSBAR, null, null, null, null, Theme.key_progressCircle), new ThemeDescription(this.searchEmptyView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite)};
    }
}
