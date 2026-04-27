package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Configuration;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.os.Environment;
import android.os.StatFs;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.ui.DocumentSelectActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BackDrawable;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.GraySectionCell;
import im.uwrkaxlmjj.ui.cells.SharedDocumentCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.NumberTextView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class DocumentSelectActivity extends BaseFragment {
    private static final int done = 3;
    private boolean allowMusic;
    private boolean canSelectOnlyImageFiles;
    private File currentDir;
    private DocumentSelectActivityDelegate delegate;
    private EmptyTextProgressView emptyView;
    private LinearLayoutManager layoutManager;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private ChatActivity parentFragment;
    private boolean scrolling;
    private NumberTextView selectedMessagesCountTextView;
    private ArrayList<ListItem> items = new ArrayList<>();
    private boolean receiverRegistered = false;
    private ArrayList<HistoryEntry> history = new ArrayList<>();
    private long sizeLimit = 1610612736;
    private HashMap<String, ListItem> selectedFiles = new HashMap<>();
    private ArrayList<View> actionModeViews = new ArrayList<>();
    private ArrayList<ListItem> recentItems = new ArrayList<>();
    private int maxSelectedFiles = -1;
    private BroadcastReceiver receiver = new AnonymousClass1();

    public interface DocumentSelectActivityDelegate {
        void didSelectFiles(DocumentSelectActivity documentSelectActivity, ArrayList<String> arrayList, boolean z, int i);

        void startDocumentSelectActivity();

        void startMusicSelectActivity(BaseFragment baseFragment);

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.DocumentSelectActivity$DocumentSelectActivityDelegate$-CC, reason: invalid class name */
        public final /* synthetic */ class CC {
            public static void $default$startMusicSelectActivity(DocumentSelectActivityDelegate _this, BaseFragment parentFragment) {
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListItem {
        String ext;
        File file;
        int icon;
        String subtitle;
        String thumb;
        String title;

        private ListItem() {
            this.subtitle = "";
            this.ext = "";
        }

        /* synthetic */ ListItem(DocumentSelectActivity x0, AnonymousClass1 x1) {
            this();
        }
    }

    private class HistoryEntry {
        File dir;
        int scrollItem;
        int scrollOffset;
        String title;

        private HistoryEntry() {
        }

        /* synthetic */ HistoryEntry(DocumentSelectActivity x0, AnonymousClass1 x1) {
            this();
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.DocumentSelectActivity$1, reason: invalid class name */
    class AnonymousClass1 extends BroadcastReceiver {
        AnonymousClass1() {
        }

        @Override // android.content.BroadcastReceiver
        public void onReceive(Context arg0, Intent intent) {
            Runnable r = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DocumentSelectActivity$1$xA0BbFGrB6cxtI_r4aJf3-OeLNM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onReceive$0$DocumentSelectActivity$1();
                }
            };
            if ("android.intent.action.MEDIA_UNMOUNTED".equals(intent.getAction())) {
                DocumentSelectActivity.this.listView.postDelayed(r, 1000L);
            } else {
                r.run();
            }
        }

        public /* synthetic */ void lambda$onReceive$0$DocumentSelectActivity$1() {
            try {
                if (DocumentSelectActivity.this.currentDir == null) {
                    DocumentSelectActivity.this.listRoots();
                } else {
                    DocumentSelectActivity.this.listFiles(DocumentSelectActivity.this.currentDir);
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    public DocumentSelectActivity(boolean music) {
        this.allowMusic = music;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        loadRecentFiles();
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        try {
            if (this.receiverRegistered) {
                ApplicationLoader.applicationContext.unregisterReceiver(this.receiver);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        super.onFragmentDestroy();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        if (!this.receiverRegistered) {
            this.receiverRegistered = true;
            IntentFilter filter = new IntentFilter();
            filter.addAction("android.intent.action.MEDIA_BAD_REMOVAL");
            filter.addAction("android.intent.action.MEDIA_CHECKING");
            filter.addAction("android.intent.action.MEDIA_EJECT");
            filter.addAction("android.intent.action.MEDIA_MOUNTED");
            filter.addAction("android.intent.action.MEDIA_NOFS");
            filter.addAction("android.intent.action.MEDIA_REMOVED");
            filter.addAction("android.intent.action.MEDIA_SHARED");
            filter.addAction("android.intent.action.MEDIA_UNMOUNTABLE");
            filter.addAction("android.intent.action.MEDIA_UNMOUNTED");
            filter.addDataScheme("file");
            ApplicationLoader.applicationContext.registerReceiver(this.receiver, filter);
        }
        this.actionBar.setBackButtonDrawable(new BackDrawable(false));
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("SelectFile", R.string.SelectFile));
        this.actionBar.setActionBarMenuOnItemClick(new AnonymousClass2());
        this.selectedFiles.clear();
        this.actionModeViews.clear();
        ActionBarMenu actionMode = this.actionBar.createActionMode();
        NumberTextView numberTextView = new NumberTextView(actionMode.getContext());
        this.selectedMessagesCountTextView = numberTextView;
        numberTextView.setTextSize(18);
        this.selectedMessagesCountTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.selectedMessagesCountTextView.setTextColor(Theme.getColor(Theme.key_actionBarActionModeDefaultIcon));
        this.selectedMessagesCountTextView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DocumentSelectActivity$zI5C4OTP33v5QMwbJ9iULaLrgxg
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return DocumentSelectActivity.lambda$createView$0(view, motionEvent);
            }
        });
        actionMode.addView(this.selectedMessagesCountTextView, LayoutHelper.createLinear(0, -1, 1.0f, 65, 0, 0, 0));
        this.actionModeViews.add(actionMode.addItemWithWidth(3, R.drawable.ic_ab_done, AndroidUtilities.dp(54.0f)));
        this.fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.emptyView = emptyTextProgressView;
        emptyTextProgressView.showTextView();
        frameLayout.addView(this.emptyView, LayoutHelper.createFrame(-1, -1.0f));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setVerticalScrollBarEnabled(false);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false);
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        this.listView.setEmptyView(this.emptyView);
        RecyclerListView recyclerListView3 = this.listView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.listAdapter = listAdapter;
        recyclerListView3.setAdapter(listAdapter);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1.0f));
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.DocumentSelectActivity.3
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                DocumentSelectActivity.this.scrolling = newState != 0;
            }
        });
        this.listView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DocumentSelectActivity$Bn2alzCTSmQIow_ibO4iUR7Kz_M
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            public final boolean onItemClick(View view, int i) {
                return this.f$0.lambda$createView$1$DocumentSelectActivity(view, i);
            }
        });
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DocumentSelectActivity$I4vt52qFusKOWgBwR-pymN7Z51Y
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$createView$3$DocumentSelectActivity(view, i);
            }
        });
        listRoots();
        return this.fragmentView;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.DocumentSelectActivity$2, reason: invalid class name */
    class AnonymousClass2 extends ActionBar.ActionBarMenuOnItemClick {
        AnonymousClass2() {
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public void onItemClick(int id) {
            if (id == -1) {
                if (DocumentSelectActivity.this.actionBar.isActionModeShowed()) {
                    DocumentSelectActivity.this.selectedFiles.clear();
                    DocumentSelectActivity.this.actionBar.hideActionMode();
                    int count = DocumentSelectActivity.this.listView.getChildCount();
                    for (int a = 0; a < count; a++) {
                        View child = DocumentSelectActivity.this.listView.getChildAt(a);
                        if (child instanceof SharedDocumentCell) {
                            ((SharedDocumentCell) child).setChecked(false, true);
                        }
                    }
                    return;
                }
                DocumentSelectActivity.this.finishFragment();
                return;
            }
            if (id == 3 && DocumentSelectActivity.this.delegate != null) {
                final ArrayList<String> files = new ArrayList<>(DocumentSelectActivity.this.selectedFiles.keySet());
                if (DocumentSelectActivity.this.parentFragment != null && DocumentSelectActivity.this.parentFragment.isInScheduleMode()) {
                    AlertsCreator.createScheduleDatePickerDialog(DocumentSelectActivity.this.getParentActivity(), UserObject.isUserSelf(DocumentSelectActivity.this.parentFragment.getCurrentUser()), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DocumentSelectActivity$2$H_M9d6LMwLAoKS1myvEcdr-_V5U
                        @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                        public final void didSelectDate(boolean z, int i) {
                            this.f$0.lambda$onItemClick$0$DocumentSelectActivity$2(files, z, i);
                        }
                    });
                } else {
                    DocumentSelectActivity.this.delegate.didSelectFiles(DocumentSelectActivity.this, files, true, 0);
                }
            }
        }

        public /* synthetic */ void lambda$onItemClick$0$DocumentSelectActivity$2(ArrayList files, boolean notify, int scheduleDate) {
            DocumentSelectActivity.this.delegate.didSelectFiles(DocumentSelectActivity.this, files, notify, scheduleDate);
        }
    }

    static /* synthetic */ boolean lambda$createView$0(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ boolean lambda$createView$1$DocumentSelectActivity(View view, int position) {
        ListItem item;
        if (this.actionBar.isActionModeShowed() || (item = this.listAdapter.getItem(position)) == null) {
            return false;
        }
        File file = item.file;
        if (file != null && !file.isDirectory()) {
            if (!file.canRead()) {
                showErrorBox(LocaleController.getString("AccessError", R.string.AccessError));
                return false;
            }
            if (this.canSelectOnlyImageFiles && item.thumb == null) {
                showErrorBox(LocaleController.formatString("PassportUploadNotImage", R.string.PassportUploadNotImage, new Object[0]));
                return false;
            }
            if (this.sizeLimit != 0) {
                long length = file.length();
                long j = this.sizeLimit;
                if (length > j) {
                    showErrorBox(LocaleController.formatString("FileUploadLimit", R.string.FileUploadLimit, AndroidUtilities.formatFileSize(j)));
                    return false;
                }
            }
            if (this.maxSelectedFiles >= 0) {
                int size = this.selectedFiles.size();
                int i = this.maxSelectedFiles;
                if (size >= i) {
                    showErrorBox(LocaleController.formatString("PassportUploadMaxReached", R.string.PassportUploadMaxReached, LocaleController.formatPluralString("Files", i)));
                    return false;
                }
            }
            if (file.length() == 0) {
                return false;
            }
            this.selectedFiles.put(file.toString(), item);
            this.selectedMessagesCountTextView.setNumber(1, false);
            AnimatorSet animatorSet = new AnimatorSet();
            ArrayList<Animator> animators = new ArrayList<>();
            for (int a = 0; a < this.actionModeViews.size(); a++) {
                View view2 = this.actionModeViews.get(a);
                AndroidUtilities.clearDrawableAnimation(view2);
                animators.add(ObjectAnimator.ofFloat(view2, "scaleY", 0.1f, 1.0f));
            }
            animatorSet.playTogether(animators);
            animatorSet.setDuration(250L);
            animatorSet.start();
            this.scrolling = false;
            if (view instanceof SharedDocumentCell) {
                ((SharedDocumentCell) view).setChecked(true, true);
            }
            this.actionBar.showActionMode();
        }
        return true;
    }

    public /* synthetic */ void lambda$createView$3$DocumentSelectActivity(View view, int position) {
        ListItem item = this.listAdapter.getItem(position);
        if (item == null) {
            return;
        }
        File file = item.file;
        if (file == null) {
            if (item.icon == R.drawable.ic_storage_gallery) {
                DocumentSelectActivityDelegate documentSelectActivityDelegate = this.delegate;
                if (documentSelectActivityDelegate != null) {
                    documentSelectActivityDelegate.startDocumentSelectActivity();
                }
                finishFragment(false);
                return;
            }
            if (item.icon == R.drawable.ic_storage_music) {
                DocumentSelectActivityDelegate documentSelectActivityDelegate2 = this.delegate;
                if (documentSelectActivityDelegate2 != null) {
                    documentSelectActivityDelegate2.startMusicSelectActivity(this);
                    return;
                }
                return;
            }
            ArrayList<HistoryEntry> arrayList = this.history;
            HistoryEntry he = arrayList.remove(arrayList.size() - 1);
            this.actionBar.setTitle(he.title);
            if (he.dir != null) {
                listFiles(he.dir);
            } else {
                listRoots();
            }
            this.layoutManager.scrollToPositionWithOffset(he.scrollItem, he.scrollOffset);
            return;
        }
        if (file.isDirectory()) {
            HistoryEntry he2 = new HistoryEntry(this, null);
            he2.scrollItem = this.layoutManager.findLastVisibleItemPosition();
            View topView = this.layoutManager.findViewByPosition(he2.scrollItem);
            if (topView != null) {
                he2.scrollOffset = topView.getTop();
            }
            he2.dir = this.currentDir;
            he2.title = this.actionBar.getTitle();
            this.history.add(he2);
            if (!listFiles(file)) {
                this.history.remove(he2);
                return;
            } else {
                this.actionBar.setTitle(item.title);
                return;
            }
        }
        if (!file.canRead()) {
            showErrorBox(LocaleController.getString("AccessError", R.string.AccessError));
            file = new File("/mnt/sdcard");
        }
        if (this.canSelectOnlyImageFiles && item.thumb == null) {
            showErrorBox(LocaleController.formatString("PassportUploadNotImage", R.string.PassportUploadNotImage, new Object[0]));
            return;
        }
        if (this.sizeLimit != 0) {
            long length = file.length();
            long j = this.sizeLimit;
            if (length > j) {
                showErrorBox(LocaleController.formatString("FileUploadLimit", R.string.FileUploadLimit, AndroidUtilities.formatFileSize(j)));
                return;
            }
        }
        if (file.length() == 0) {
            return;
        }
        if (this.actionBar.isActionModeShowed()) {
            if (this.selectedFiles.containsKey(file.toString())) {
                this.selectedFiles.remove(file.toString());
            } else {
                if (this.maxSelectedFiles >= 0) {
                    int size = this.selectedFiles.size();
                    int i = this.maxSelectedFiles;
                    if (size >= i) {
                        showErrorBox(LocaleController.formatString("PassportUploadMaxReached", R.string.PassportUploadMaxReached, LocaleController.formatPluralString("Files", i)));
                        return;
                    }
                }
                this.selectedFiles.put(file.toString(), item);
            }
            if (this.selectedFiles.isEmpty()) {
                this.actionBar.hideActionMode();
            } else {
                this.selectedMessagesCountTextView.setNumber(this.selectedFiles.size(), true);
            }
            this.scrolling = false;
            if (view instanceof SharedDocumentCell) {
                ((SharedDocumentCell) view).setChecked(this.selectedFiles.containsKey(item.file.toString()), true);
                return;
            }
            return;
        }
        if (this.delegate != null) {
            final ArrayList<String> files = new ArrayList<>();
            files.add(file.getAbsolutePath());
            ChatActivity chatActivity = this.parentFragment;
            if (chatActivity == null || !chatActivity.isInScheduleMode()) {
                this.delegate.didSelectFiles(this, files, true, 0);
            } else {
                AlertsCreator.createScheduleDatePickerDialog(getParentActivity(), UserObject.isUserSelf(this.parentFragment.getCurrentUser()), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DocumentSelectActivity$Z0-cKphkQksc9ysOSQTBwFDiGYI
                    @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                    public final void didSelectDate(boolean z, int i2) {
                        this.f$0.lambda$null$2$DocumentSelectActivity(files, z, i2);
                    }
                });
            }
        }
    }

    public /* synthetic */ void lambda$null$2$DocumentSelectActivity(ArrayList files, boolean notify, int scheduleDate) {
        this.delegate.didSelectFiles(this, files, notify, scheduleDate);
    }

    public void setChatActivity(ChatActivity chatActivity) {
        this.parentFragment = chatActivity;
    }

    public void setMaxSelectedFiles(int value) {
        this.maxSelectedFiles = value;
    }

    public void setCanSelectOnlyImageFiles(boolean value) {
        this.canSelectOnlyImageFiles = true;
    }

    public void loadRecentFiles() {
        try {
            File[] files = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).listFiles();
            for (File file : files) {
                if (!file.isDirectory()) {
                    ListItem item = new ListItem(this, null);
                    item.title = file.getName();
                    item.file = file;
                    String fname = file.getName();
                    String[] sp = fname.split("\\.");
                    item.ext = sp.length > 1 ? sp[sp.length - 1] : "?";
                    item.subtitle = AndroidUtilities.formatFileSize(file.length());
                    String fname2 = fname.toLowerCase();
                    if (fname2.endsWith(".jpg") || fname2.endsWith(".png") || fname2.endsWith(".gif") || fname2.endsWith(".jpeg")) {
                        item.thumb = file.getAbsolutePath();
                    }
                    this.recentItems.add(item);
                }
            }
            Collections.sort(this.recentItems, new Comparator() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DocumentSelectActivity$RfQh7NZkostT7p6h8J61_ocDQ8E
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return DocumentSelectActivity.lambda$loadRecentFiles$4((DocumentSelectActivity.ListItem) obj, (DocumentSelectActivity.ListItem) obj2);
                }
            });
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    static /* synthetic */ int lambda$loadRecentFiles$4(ListItem o1, ListItem o2) {
        long lm = o1.file.lastModified();
        long rm = o2.file.lastModified();
        if (lm == rm) {
            return 0;
        }
        if (lm > rm) {
            return -1;
        }
        return 1;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
        fixLayoutInternal();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            ViewTreeObserver obs = recyclerListView.getViewTreeObserver();
            obs.addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() { // from class: im.uwrkaxlmjj.ui.DocumentSelectActivity.4
                @Override // android.view.ViewTreeObserver.OnPreDrawListener
                public boolean onPreDraw() {
                    DocumentSelectActivity.this.listView.getViewTreeObserver().removeOnPreDrawListener(this);
                    DocumentSelectActivity.this.fixLayoutInternal();
                    return true;
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void fixLayoutInternal() {
        if (this.selectedMessagesCountTextView == null) {
            return;
        }
        if (!AndroidUtilities.isTablet() && ApplicationLoader.applicationContext.getResources().getConfiguration().orientation == 2) {
            this.selectedMessagesCountTextView.setTextSize(18);
        } else {
            this.selectedMessagesCountTextView.setTextSize(20);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        if (this.history.size() > 0) {
            HistoryEntry he = this.history.remove(r0.size() - 1);
            this.actionBar.setTitle(he.title);
            if (he.dir != null) {
                listFiles(he.dir);
            } else {
                listRoots();
            }
            this.layoutManager.scrollToPositionWithOffset(he.scrollItem, he.scrollOffset);
            return false;
        }
        return super.onBackPressed();
    }

    public void setDelegate(DocumentSelectActivityDelegate delegate) {
        this.delegate = delegate;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean listFiles(File dir) {
        AnonymousClass1 anonymousClass1;
        if (!dir.canRead()) {
            if ((dir.getAbsolutePath().startsWith(Environment.getExternalStorageDirectory().toString()) || dir.getAbsolutePath().startsWith("/sdcard") || dir.getAbsolutePath().startsWith("/mnt/sdcard")) && !Environment.getExternalStorageState().equals("mounted") && !Environment.getExternalStorageState().equals("mounted_ro")) {
                this.currentDir = dir;
                this.items.clear();
                String state = Environment.getExternalStorageState();
                if ("shared".equals(state)) {
                    this.emptyView.setText(LocaleController.getString("UsbActive", R.string.UsbActive));
                } else {
                    this.emptyView.setText(LocaleController.getString("NotMounted", R.string.NotMounted));
                }
                AndroidUtilities.clearDrawableAnimation(this.listView);
                this.scrolling = true;
                this.listAdapter.notifyDataSetChanged();
                return true;
            }
            showErrorBox(LocaleController.getString("AccessError", R.string.AccessError));
            return false;
        }
        try {
            File[] files = dir.listFiles();
            if (files == null) {
                showErrorBox(LocaleController.getString("UnknownError", R.string.UnknownError));
                return false;
            }
            this.currentDir = dir;
            this.items.clear();
            Arrays.sort(files, new Comparator() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DocumentSelectActivity$EC5003izj9de8xuYj8ehETIGrR8
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return DocumentSelectActivity.lambda$listFiles$5((File) obj, (File) obj2);
                }
            });
            int a = 0;
            while (true) {
                anonymousClass1 = null;
                if (a >= files.length) {
                    break;
                }
                File file = files[a];
                if (file.getName().indexOf(46) != 0) {
                    ListItem item = new ListItem(this, anonymousClass1);
                    item.title = file.getName();
                    item.file = file;
                    if (file.isDirectory()) {
                        item.icon = R.drawable.ic_directory;
                        item.subtitle = LocaleController.getString("Folder", R.string.Folder);
                    } else {
                        String fname = file.getName();
                        String[] sp = fname.split("\\.");
                        item.ext = sp.length > 1 ? sp[sp.length - 1] : "?";
                        item.subtitle = AndroidUtilities.formatFileSize(file.length());
                        String fname2 = fname.toLowerCase();
                        if (fname2.endsWith(".jpg") || fname2.endsWith(".png") || fname2.endsWith(".gif") || fname2.endsWith(".jpeg")) {
                            item.thumb = file.getAbsolutePath();
                        }
                    }
                    this.items.add(item);
                }
                a++;
            }
            ListItem item2 = new ListItem(this, anonymousClass1);
            item2.title = "..";
            if (this.history.size() > 0) {
                ArrayList<HistoryEntry> arrayList = this.history;
                HistoryEntry entry = arrayList.get(arrayList.size() - 1);
                if (entry.dir == null) {
                    item2.subtitle = LocaleController.getString("Folder", R.string.Folder);
                } else {
                    item2.subtitle = entry.dir.toString();
                }
            } else {
                item2.subtitle = LocaleController.getString("Folder", R.string.Folder);
            }
            item2.icon = R.drawable.ic_directory;
            item2.file = null;
            this.items.add(0, item2);
            AndroidUtilities.clearDrawableAnimation(this.listView);
            this.scrolling = true;
            this.listAdapter.notifyDataSetChanged();
            return true;
        } catch (Exception e) {
            showErrorBox(e.getLocalizedMessage());
            return false;
        }
    }

    static /* synthetic */ int lambda$listFiles$5(File lhs, File rhs) {
        if (lhs.isDirectory() != rhs.isDirectory()) {
            return lhs.isDirectory() ? -1 : 1;
        }
        return lhs.getName().compareToIgnoreCase(rhs.getName());
    }

    private void showErrorBox(String error) {
        if (getParentActivity() == null) {
            return;
        }
        new AlertDialog.Builder(getParentActivity()).setTitle(LocaleController.getString("AppName", R.string.AppName)).setMessage(error).setPositiveButton(LocaleController.getString("OK", R.string.OK), null).show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:44:0x011c  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0131 A[Catch: Exception -> 0x015d, all -> 0x017d, TryCatch #0 {Exception -> 0x015d, blocks: (B:46:0x0120, B:48:0x0131, B:49:0x0138), top: B:92:0x0120 }] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0138 A[Catch: Exception -> 0x015d, all -> 0x017d, TRY_LEAVE, TryCatch #0 {Exception -> 0x015d, blocks: (B:46:0x0120, B:48:0x0131, B:49:0x0138), top: B:92:0x0120 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void listRoots() {
        /*
            Method dump skipped, instruction units count: 595
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.DocumentSelectActivity.listRoots():void");
    }

    private String getRootSubtitle(String path) {
        try {
            StatFs stat = new StatFs(path);
            long total = ((long) stat.getBlockCount()) * ((long) stat.getBlockSize());
            long free = ((long) stat.getAvailableBlocks()) * ((long) stat.getBlockSize());
            if (total == 0) {
                return "";
            }
            return LocaleController.formatString("FreeOfTotal", R.string.FreeOfTotal, AndroidUtilities.formatFileSize(free), AndroidUtilities.formatFileSize(total));
        } catch (Exception e) {
            FileLog.e(e);
            return path;
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() != 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int count = DocumentSelectActivity.this.items.size();
            if (DocumentSelectActivity.this.history.isEmpty() && !DocumentSelectActivity.this.recentItems.isEmpty()) {
                return count + DocumentSelectActivity.this.recentItems.size() + 1;
            }
            return count;
        }

        public ListItem getItem(int position) {
            int position2;
            if (position < DocumentSelectActivity.this.items.size()) {
                return (ListItem) DocumentSelectActivity.this.items.get(position);
            }
            if (DocumentSelectActivity.this.history.isEmpty() && !DocumentSelectActivity.this.recentItems.isEmpty() && position != DocumentSelectActivity.this.items.size() && (position2 = position - (DocumentSelectActivity.this.items.size() + 1)) < DocumentSelectActivity.this.recentItems.size()) {
                return (ListItem) DocumentSelectActivity.this.recentItems.get(position2);
            }
            return null;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return getItem(position) != null ? 1 : 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new GraySectionCell(this.mContext);
                ((GraySectionCell) view).setText(LocaleController.getString("Recent", R.string.Recent));
            } else {
                view = new SharedDocumentCell(this.mContext);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            if (holder.getItemViewType() == 1) {
                ListItem item = getItem(position);
                SharedDocumentCell documentCell = (SharedDocumentCell) holder.itemView;
                if (item.icon != 0) {
                    documentCell.setTextAndValueAndTypeAndThumb(item.title, item.subtitle, null, null, item.icon);
                } else {
                    String type = item.ext.toUpperCase().substring(0, Math.min(item.ext.length(), 4));
                    documentCell.setTextAndValueAndTypeAndThumb(item.title, item.subtitle, type, item.thumb, 0);
                }
                if (item.file == null || !DocumentSelectActivity.this.actionBar.isActionModeShowed()) {
                    documentCell.setChecked(false, true ^ DocumentSelectActivity.this.scrolling);
                } else {
                    documentCell.setChecked(DocumentSelectActivity.this.selectedFiles.containsKey(item.file.toString()), true ^ DocumentSelectActivity.this.scrolling);
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.emptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_emptyListPlaceholder), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_AM_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarActionModeDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_AM_BACKGROUND, null, null, null, null, Theme.key_actionBarActionModeDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_AM_TOPBACKGROUND, null, null, null, null, Theme.key_actionBarActionModeDefaultTop), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_AM_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarActionModeDefaultSelector), new ThemeDescription(this.selectedMessagesCountTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_actionBarActionModeDefaultIcon), new ThemeDescription(this.listView, 0, new Class[]{GraySectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_graySectionText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{GraySectionCell.class}, null, null, null, Theme.key_graySection), new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{SharedDocumentCell.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{SharedDocumentCell.class}, new String[]{"dateTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText3), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKBOX, new Class[]{SharedDocumentCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_checkbox), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKBOXCHECK, new Class[]{SharedDocumentCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_checkboxCheck), new ThemeDescription(this.listView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{SharedDocumentCell.class}, new String[]{"thumbImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_files_folderIcon), new ThemeDescription(this.listView, ThemeDescription.FLAG_IMAGECOLOR | ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{SharedDocumentCell.class}, new String[]{"thumbImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_files_folderIconBackground), new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{SharedDocumentCell.class}, new String[]{"extTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_files_iconText)};
    }
}
