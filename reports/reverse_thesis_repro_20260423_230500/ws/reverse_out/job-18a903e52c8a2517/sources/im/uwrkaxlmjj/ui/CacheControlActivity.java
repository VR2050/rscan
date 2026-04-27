package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.CheckBoxCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.io.File;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class CacheControlActivity extends BaseFragment {
    private int cacheInfoRow;
    private int cacheRow;
    private int databaseInfoRow;
    private int databaseRow;
    private int keepMediaInfoRow;
    private int keepMediaRow;
    private LinearLayoutManager layoutManager;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private int rowCount;
    private long databaseSize = -1;
    private long cacheSize = -1;
    private long documentsSize = -1;
    private long audioSize = -1;
    private long musicSize = -1;
    private long photoSize = -1;
    private long videoSize = -1;
    private long totalSize = -1;
    private boolean[] clear = new boolean[6];
    private boolean calculating = true;
    private volatile boolean canceled = false;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        this.rowCount = 0;
        int i = 0 + 1;
        this.rowCount = i;
        this.keepMediaRow = 0;
        int i2 = i + 1;
        this.rowCount = i2;
        this.keepMediaInfoRow = i;
        int i3 = i2 + 1;
        this.rowCount = i3;
        this.cacheRow = i2;
        int i4 = i3 + 1;
        this.rowCount = i4;
        this.cacheInfoRow = i3;
        int i5 = i4 + 1;
        this.rowCount = i5;
        this.databaseRow = i4;
        this.rowCount = i5 + 1;
        this.databaseInfoRow = i5;
        this.databaseSize = MessagesStorage.getInstance(this.currentAccount).getDatabaseSize();
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CacheControlActivity$UZGzw9jCPtt5ouhDskttG-0k4d8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onFragmentCreate$1$CacheControlActivity();
            }
        });
        return true;
    }

    public /* synthetic */ void lambda$onFragmentCreate$1$CacheControlActivity() {
        this.cacheSize = getDirectorySize(FileLoader.checkDirectory(4), 0);
        if (this.canceled) {
            return;
        }
        this.photoSize = getDirectorySize(FileLoader.checkDirectory(0), 0);
        if (this.canceled) {
            return;
        }
        this.videoSize = getDirectorySize(FileLoader.checkDirectory(2), 0);
        if (this.canceled) {
            return;
        }
        this.documentsSize = getDirectorySize(FileLoader.checkDirectory(3), 1);
        if (!this.canceled) {
            this.musicSize = getDirectorySize(FileLoader.checkDirectory(3), 2);
            if (this.canceled) {
                return;
            }
            long directorySize = getDirectorySize(FileLoader.checkDirectory(1), 0);
            this.audioSize = directorySize;
            this.totalSize = this.cacheSize + this.videoSize + directorySize + this.photoSize + this.documentsSize + this.musicSize;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CacheControlActivity$yFoSmZQOZvLJOU7t98SbOWQ5_lY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$CacheControlActivity();
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$0$CacheControlActivity() {
        this.calculating = false;
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        this.canceled = true;
    }

    private long getDirectorySize(File dir, int documentsMusicType) {
        if (dir == null || this.canceled) {
            return 0L;
        }
        if (dir.isDirectory()) {
            long size = Utilities.getDirSize(dir.getAbsolutePath(), documentsMusicType);
            return size;
        }
        if (dir.isFile()) {
            long size2 = 0 + dir.length();
            return size2;
        }
        return 0L;
    }

    private void cleanupFolders() {
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        progressDialog.setCanCancel(false);
        progressDialog.show();
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CacheControlActivity$DfPItK69EkP-is2_lwb35ApSw9k
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$cleanupFolders$3$CacheControlActivity(progressDialog);
            }
        });
    }

    public /* synthetic */ void lambda$cleanupFolders$3$CacheControlActivity(final AlertDialog progressDialog) {
        boolean imagesCleared = false;
        for (int a = 0; a < 6; a++) {
            if (this.clear[a]) {
                int type = -1;
                int documentsMusicType = 0;
                if (a == 0) {
                    type = 0;
                } else if (a == 1) {
                    type = 2;
                } else if (a == 2) {
                    type = 3;
                    documentsMusicType = 1;
                } else if (a == 3) {
                    type = 3;
                    documentsMusicType = 2;
                } else if (a == 4) {
                    type = 1;
                } else if (a == 5) {
                    type = 4;
                }
                if (type != -1) {
                    File file = FileLoader.checkDirectory(type);
                    if (file != null) {
                        Utilities.clearDir(file.getAbsolutePath(), documentsMusicType, Long.MAX_VALUE);
                    }
                    if (type == 4) {
                        this.cacheSize = getDirectorySize(FileLoader.checkDirectory(4), documentsMusicType);
                        imagesCleared = true;
                    } else if (type == 1) {
                        this.audioSize = getDirectorySize(FileLoader.checkDirectory(1), documentsMusicType);
                    } else if (type == 3) {
                        if (documentsMusicType == 1) {
                            this.documentsSize = getDirectorySize(FileLoader.checkDirectory(3), documentsMusicType);
                        } else {
                            this.musicSize = getDirectorySize(FileLoader.checkDirectory(3), documentsMusicType);
                        }
                    } else if (type == 0) {
                        imagesCleared = true;
                        this.photoSize = getDirectorySize(FileLoader.checkDirectory(0), documentsMusicType);
                    } else if (type == 2) {
                        this.videoSize = getDirectorySize(FileLoader.checkDirectory(2), documentsMusicType);
                    }
                }
            }
        }
        final boolean imagesClearedFinal = imagesCleared;
        this.totalSize = this.cacheSize + this.videoSize + this.audioSize + this.photoSize + this.documentsSize + this.musicSize;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CacheControlActivity$MgOJbqDly-4Sxa1LmbirtoMfFMI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$CacheControlActivity(imagesClearedFinal, progressDialog);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$CacheControlActivity(boolean imagesClearedFinal, AlertDialog progressDialog) {
        if (imagesClearedFinal) {
            ImageLoader.getInstance().clearMemory();
        }
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("ClearMediaCache", R.string.ClearMediaCache));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.CacheControlActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    CacheControlActivity.this.finishFragment();
                }
            }
        });
        this.listAdapter = new ListAdapter(context);
        this.fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setVerticalScrollBarEnabled(false);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false);
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1.0f));
        this.listView.setAdapter(this.listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CacheControlActivity$4xe4ybmLYCV7Q_GtNZo9iyoJo9s
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$createView$7$CacheControlActivity(view, i);
            }
        });
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$7$CacheControlActivity(View view, int position) {
        if (getParentActivity() == null) {
            return;
        }
        if (position != this.keepMediaRow) {
            if (position == this.databaseRow || position != this.cacheRow || this.totalSize <= 0 || getParentActivity() == null) {
                return;
            }
            BottomSheet.Builder builder = new BottomSheet.Builder(getParentActivity());
            builder.setApplyTopPadding(false);
            builder.setApplyBottomPadding(false);
            LinearLayout linearLayout = new LinearLayout(getParentActivity());
            linearLayout.setOrientation(1);
            for (int a = 0; a < 6; a++) {
                long size = 0;
                String name = null;
                if (a == 0) {
                    long size2 = this.photoSize;
                    name = LocaleController.getString("LocalPhotoCache", R.string.LocalPhotoCache);
                    size = size2;
                } else if (a == 1) {
                    long size3 = this.videoSize;
                    name = LocaleController.getString("LocalVideoCache", R.string.LocalVideoCache);
                    size = size3;
                } else if (a == 2) {
                    long size4 = this.documentsSize;
                    name = LocaleController.getString("LocalDocumentCache", R.string.LocalDocumentCache);
                    size = size4;
                } else if (a == 3) {
                    long size5 = this.musicSize;
                    name = LocaleController.getString("LocalMusicCache", R.string.LocalMusicCache);
                    size = size5;
                } else if (a == 4) {
                    long size6 = this.audioSize;
                    name = LocaleController.getString("LocalAudioCache", R.string.LocalAudioCache);
                    size = size6;
                } else if (a == 5) {
                    long size7 = this.cacheSize;
                    name = LocaleController.getString("LocalCache", R.string.LocalCache);
                    size = size7;
                }
                if (size > 0) {
                    this.clear[a] = true;
                    CheckBoxCell checkBoxCell = new CheckBoxCell(getParentActivity(), 1, 21);
                    checkBoxCell.setTag(Integer.valueOf(a));
                    checkBoxCell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
                    linearLayout.addView(checkBoxCell, LayoutHelper.createLinear(-1, 50));
                    checkBoxCell.setText(name, AndroidUtilities.formatFileSize(size), true, true);
                    checkBoxCell.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
                    checkBoxCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CacheControlActivity$B_I6rzyMCaMaMYwOuDatMeAdQho
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view2) {
                            this.f$0.lambda$null$5$CacheControlActivity(view2);
                        }
                    });
                } else {
                    this.clear[a] = false;
                }
            }
            BottomSheet.BottomSheetCell cell = new BottomSheet.BottomSheetCell(getParentActivity(), 1);
            cell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
            cell.setTextAndIcon(LocaleController.getString("ClearMediaCache", R.string.ClearMediaCache).toUpperCase(), 0);
            cell.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText));
            cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CacheControlActivity$JnrRexLpKks0hXVVzHQzvXJp5pk
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$null$6$CacheControlActivity(view2);
                }
            });
            linearLayout.addView(cell, LayoutHelper.createLinear(-1, 50));
            builder.setCustomView(linearLayout);
            showDialog(builder.create());
            return;
        }
        BottomSheet.Builder builder2 = new BottomSheet.Builder(getParentActivity());
        builder2.setItems(new CharSequence[]{LocaleController.formatPluralString("Days", 3), LocaleController.formatPluralString("Weeks", 1), LocaleController.formatPluralString("Months", 1), LocaleController.getString("KeepMediaForever", R.string.KeepMediaForever)}, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CacheControlActivity$iWESbRoNG-KvxbN7LVWUJnnNTJ4
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$4$CacheControlActivity(dialogInterface, i);
            }
        });
        showDialog(builder2.create());
    }

    public /* synthetic */ void lambda$null$4$CacheControlActivity(DialogInterface dialog, int which) {
        if (which == 0) {
            SharedConfig.setKeepMedia(3);
        } else if (which == 1) {
            SharedConfig.setKeepMedia(0);
        } else if (which == 2) {
            SharedConfig.setKeepMedia(1);
        } else if (which == 3) {
            SharedConfig.setKeepMedia(2);
        }
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
        SharedConfig.checkKeepMedia();
    }

    public /* synthetic */ void lambda$null$5$CacheControlActivity(View v) {
        CheckBoxCell cell = (CheckBoxCell) v;
        int num = ((Integer) cell.getTag()).intValue();
        boolean[] zArr = this.clear;
        zArr[num] = !zArr[num];
        cell.setChecked(zArr[num], true);
    }

    public /* synthetic */ void lambda$null$6$CacheControlActivity(View v) {
        try {
            if (this.visibleDialog != null) {
                this.visibleDialog.dismiss();
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        cleanupFolders();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return position == CacheControlActivity.this.databaseRow || (position == CacheControlActivity.this.cacheRow && CacheControlActivity.this.totalSize > 0) || position == CacheControlActivity.this.keepMediaRow;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return CacheControlActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new TextSettingsCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else {
                view = new TextInfoPrivacyCell(this.mContext);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String value;
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType == 1) {
                    TextInfoPrivacyCell privacyCell = (TextInfoPrivacyCell) holder.itemView;
                    if (position != CacheControlActivity.this.databaseInfoRow) {
                        if (position != CacheControlActivity.this.cacheInfoRow) {
                            if (position == CacheControlActivity.this.keepMediaInfoRow) {
                                privacyCell.setText(AndroidUtilities.replaceTags(LocaleController.getString("KeepMediaInfo", R.string.KeepMediaInfo)));
                                privacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                                return;
                            }
                            return;
                        }
                        privacyCell.setText("");
                        privacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                        return;
                    }
                    privacyCell.setText(LocaleController.getString("LocalDatabaseInfo", R.string.LocalDatabaseInfo));
                    privacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                    return;
                }
                return;
            }
            TextSettingsCell textCell = (TextSettingsCell) holder.itemView;
            if (position == CacheControlActivity.this.databaseRow) {
                textCell.setTextAndValue(LocaleController.getString("LocalDatabase", R.string.LocalDatabase), AndroidUtilities.formatFileSize(CacheControlActivity.this.databaseSize), false);
                return;
            }
            if (position == CacheControlActivity.this.cacheRow) {
                if (!CacheControlActivity.this.calculating) {
                    textCell.setTextAndValue(LocaleController.getString("ClearMediaCache", R.string.ClearMediaCache), CacheControlActivity.this.totalSize == 0 ? LocaleController.getString("CacheEmpty", R.string.CacheEmpty) : AndroidUtilities.formatFileSize(CacheControlActivity.this.totalSize), false);
                    return;
                } else {
                    textCell.setTextAndValue(LocaleController.getString("ClearMediaCache", R.string.ClearMediaCache), LocaleController.getString("CalculatingSize", R.string.CalculatingSize), false);
                    return;
                }
            }
            if (position == CacheControlActivity.this.keepMediaRow) {
                MessagesController.getGlobalMainSettings();
                int keepMedia = SharedConfig.keepMedia;
                if (keepMedia == 0) {
                    value = LocaleController.formatPluralString("Weeks", 1);
                } else if (keepMedia == 1) {
                    value = LocaleController.formatPluralString("Months", 1);
                } else if (keepMedia == 3) {
                    value = LocaleController.formatPluralString("Days", 3);
                } else {
                    value = LocaleController.getString("KeepMediaForever", R.string.KeepMediaForever);
                }
                textCell.setTextAndValue(LocaleController.getString("KeepMedia", R.string.KeepMedia), value, false);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            if (i == CacheControlActivity.this.databaseInfoRow || i == CacheControlActivity.this.cacheInfoRow || i == CacheControlActivity.this.keepMediaInfoRow) {
                return 1;
            }
            return 0;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{TextSettingsCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4)};
    }
}
