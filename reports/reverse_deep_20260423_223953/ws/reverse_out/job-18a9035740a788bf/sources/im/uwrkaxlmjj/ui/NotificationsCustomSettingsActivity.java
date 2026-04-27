package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.media.Ringtone;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcelable;
import android.provider.Settings;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.exoplayer2.upstream.cache.ContentMetadata;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.NotificationsSettingsActivity;
import im.uwrkaxlmjj.ui.ProfileNotificationsActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper;
import im.uwrkaxlmjj.ui.cells.GraySectionCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.NotificationsCheckCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextCell;
import im.uwrkaxlmjj.ui.cells.TextCheckCell;
import im.uwrkaxlmjj.ui.cells.TextColorCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.cells.UserCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.ArrayList;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class NotificationsCustomSettingsActivity extends BaseFragment {
    private static final int search_button = 0;
    private ListAdapter adapter;
    private int alertRow;
    private int alertSection2Row;
    private AnimatorSet animatorSet;
    private int currentType;
    private int deleteAllRow;
    private int deleteAllSectionRow;
    private EmptyTextProgressView emptyView;
    private ArrayList<NotificationsSettingsActivity.NotificationException> exceptions;
    private int exceptionsAddRow;
    private HashMap<Long, NotificationsSettingsActivity.NotificationException> exceptionsDict;
    private int exceptionsEndRow;
    private int exceptionsSection2Row;
    private int exceptionsStartRow;
    private int groupSection2Row;
    private RecyclerListView listView;
    private int messageLedRow;
    private int messagePopupNotificationRow;
    private int messagePriorityRow;
    private int messageSectionRow;
    private int messageSoundRow;
    private int messageVibrateRow;
    private int previewRow;
    private int rowCount;
    private SearchAdapter searchAdapter;
    private boolean searchWas;
    private boolean searching;

    public NotificationsCustomSettingsActivity(int type, ArrayList<NotificationsSettingsActivity.NotificationException> notificationExceptions) {
        this(type, notificationExceptions, false);
    }

    public NotificationsCustomSettingsActivity(int type, ArrayList<NotificationsSettingsActivity.NotificationException> notificationExceptions, boolean load) {
        this.rowCount = 0;
        this.exceptionsDict = new HashMap<>();
        this.currentType = type;
        this.exceptions = notificationExceptions;
        int N = notificationExceptions.size();
        for (int a = 0; a < N; a++) {
            NotificationsSettingsActivity.NotificationException exception = this.exceptions.get(a);
            this.exceptionsDict.put(Long.valueOf(exception.did), exception);
        }
        if (load) {
            loadExceptions();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        updateRows();
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.searching = false;
        this.searchWas = false;
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        if (this.currentType == -1) {
            this.actionBar.setTitle(LocaleController.getString("NotificationsExceptions", R.string.NotificationsExceptions));
        } else {
            this.actionBar.setTitle(LocaleController.getString("Notifications", R.string.Notifications));
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.NotificationsCustomSettingsActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    NotificationsCustomSettingsActivity.this.finishFragment();
                }
            }
        });
        ArrayList<NotificationsSettingsActivity.NotificationException> arrayList = this.exceptions;
        if (arrayList != null && !arrayList.isEmpty()) {
            ActionBarMenu menu = this.actionBar.createMenu();
            ActionBarMenuItem searchItem = menu.addItem(0, R.drawable.ic_ab_search).setIsSearchField(true).setActionBarMenuItemSearchListener(new ActionBarMenuItem.ActionBarMenuItemSearchListener() { // from class: im.uwrkaxlmjj.ui.NotificationsCustomSettingsActivity.2
                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
                public void onSearchExpand() {
                    NotificationsCustomSettingsActivity.this.searching = true;
                    NotificationsCustomSettingsActivity.this.emptyView.setShowAtCenter(true);
                }

                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
                public void onSearchCollapse() {
                    NotificationsCustomSettingsActivity.this.searchAdapter.searchDialogs(null);
                    NotificationsCustomSettingsActivity.this.searching = false;
                    NotificationsCustomSettingsActivity.this.searchWas = false;
                    NotificationsCustomSettingsActivity.this.emptyView.setText(LocaleController.getString("NoExceptions", R.string.NoExceptions));
                    NotificationsCustomSettingsActivity.this.listView.setAdapter(NotificationsCustomSettingsActivity.this.adapter);
                    NotificationsCustomSettingsActivity.this.adapter.notifyDataSetChanged();
                    NotificationsCustomSettingsActivity.this.listView.setFastScrollVisible(true);
                    NotificationsCustomSettingsActivity.this.listView.setVerticalScrollBarEnabled(false);
                    NotificationsCustomSettingsActivity.this.emptyView.setShowAtCenter(false);
                }

                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
                public void onTextChanged(EditText editText) {
                    if (NotificationsCustomSettingsActivity.this.searchAdapter == null) {
                        return;
                    }
                    String text = editText.getText().toString();
                    if (text.length() != 0) {
                        NotificationsCustomSettingsActivity.this.searchWas = true;
                        if (NotificationsCustomSettingsActivity.this.listView != null) {
                            NotificationsCustomSettingsActivity.this.emptyView.setText(LocaleController.getString("NoResult", R.string.NoResult));
                            NotificationsCustomSettingsActivity.this.emptyView.showProgress();
                            NotificationsCustomSettingsActivity.this.listView.setAdapter(NotificationsCustomSettingsActivity.this.searchAdapter);
                            NotificationsCustomSettingsActivity.this.searchAdapter.notifyDataSetChanged();
                            NotificationsCustomSettingsActivity.this.listView.setFastScrollVisible(false);
                            NotificationsCustomSettingsActivity.this.listView.setVerticalScrollBarEnabled(true);
                        }
                    }
                    NotificationsCustomSettingsActivity.this.searchAdapter.searchDialogs(text);
                }
            });
            searchItem.setSearchFieldHint(LocaleController.getString("Search", R.string.Search));
        }
        this.searchAdapter = new SearchAdapter(context);
        this.fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.emptyView = emptyTextProgressView;
        emptyTextProgressView.setTextSize(18);
        this.emptyView.setText(LocaleController.getString("NoExceptions", R.string.NoExceptions));
        this.emptyView.showTextView();
        frameLayout.addView(this.emptyView, LayoutHelper.createFrame(-1, -1.0f));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setEmptyView(this.emptyView);
        this.listView.setLayoutManager(new LinearLayoutManager(context, 1, false));
        this.listView.setVerticalScrollBarEnabled(false);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1.0f));
        RecyclerListView recyclerListView2 = this.listView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.adapter = listAdapter;
        recyclerListView2.setAdapter(listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListenerExtended() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$ooq5bfQ1lkwIvcoxt1fpaLF_Jt8
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListenerExtended
            public final void onItemClick(View view, int i, float f, float f2) {
                this.f$0.lambda$createView$9$NotificationsCustomSettingsActivity(view, i, f, f2);
            }
        });
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.NotificationsCustomSettingsActivity.3
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 1 && NotificationsCustomSettingsActivity.this.searching && NotificationsCustomSettingsActivity.this.searchWas) {
                    AndroidUtilities.hideKeyboard(NotificationsCustomSettingsActivity.this.getParentActivity().getCurrentFocus());
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
            }
        });
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$9$NotificationsCustomSettingsActivity(View view, final int position, float x, float y) {
        ArrayList<NotificationsSettingsActivity.NotificationException> arrayList;
        NotificationsSettingsActivity.NotificationException exception;
        boolean newException;
        long did;
        boolean newException2;
        NotificationsSettingsActivity.NotificationException exception2;
        NotificationsSettingsActivity.NotificationException exception3;
        boolean newException3;
        ArrayList<NotificationsSettingsActivity.NotificationException> arrayList2;
        String key;
        String path;
        boolean enabled = false;
        if (getParentActivity() != null) {
            if (this.listView.getAdapter() == this.searchAdapter || (position >= this.exceptionsStartRow && position < this.exceptionsEndRow)) {
                RecyclerView.Adapter adapter = this.listView.getAdapter();
                SearchAdapter searchAdapter = this.searchAdapter;
                if (adapter == searchAdapter) {
                    Object object = searchAdapter.getObject(position);
                    if (!(object instanceof NotificationsSettingsActivity.NotificationException)) {
                        if (object instanceof TLRPC.User) {
                            TLRPC.User user = (TLRPC.User) object;
                            did = user.id;
                        } else {
                            TLRPC.Chat chat = (TLRPC.Chat) object;
                            did = -chat.id;
                        }
                        if (this.exceptionsDict.containsKey(Long.valueOf(did))) {
                            exception2 = this.exceptionsDict.get(Long.valueOf(did));
                            newException2 = false;
                        } else {
                            NotificationsSettingsActivity.NotificationException exception4 = new NotificationsSettingsActivity.NotificationException();
                            exception4.did = did;
                            if (object instanceof TLRPC.User) {
                                TLRPC.User user2 = (TLRPC.User) object;
                                exception4.did = user2.id;
                            } else {
                                TLRPC.Chat chat2 = (TLRPC.Chat) object;
                                exception4.did = -chat2.id;
                            }
                            newException2 = true;
                            exception2 = exception4;
                        }
                        exception3 = exception2;
                        newException3 = newException2;
                        arrayList2 = this.exceptions;
                    } else {
                        arrayList2 = this.searchAdapter.searchResult;
                        exception3 = (NotificationsSettingsActivity.NotificationException) object;
                        newException3 = false;
                    }
                    arrayList = arrayList2;
                    exception = exception3;
                    newException = newException3;
                } else {
                    ArrayList<NotificationsSettingsActivity.NotificationException> arrayList3 = this.exceptions;
                    int index = position - this.exceptionsStartRow;
                    if (index < 0 || index >= arrayList3.size()) {
                        return;
                    }
                    NotificationsSettingsActivity.NotificationException exception5 = arrayList3.get(index);
                    arrayList = arrayList3;
                    exception = exception5;
                    newException = false;
                }
                if (exception != null) {
                    final boolean z = newException;
                    final ArrayList<NotificationsSettingsActivity.NotificationException> arrayList4 = arrayList;
                    final NotificationsSettingsActivity.NotificationException notificationException = exception;
                    AlertsCreator.showCustomNotificationsDialog(this, exception.did, -1, null, this.currentAccount, null, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$p3fdj6pL4wDxgspVW5KLhHsR1MM
                        @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
                        public final void run(int i) {
                            this.f$0.lambda$null$0$NotificationsCustomSettingsActivity(z, arrayList4, notificationException, position, i);
                        }
                    });
                    return;
                }
                return;
            }
            if (position != this.exceptionsAddRow) {
                if (position != this.deleteAllRow) {
                    if (position == this.alertRow) {
                        enabled = getNotificationsController().isGlobalNotificationsEnabled(this.currentType);
                        final NotificationsCheckCell checkCell = (NotificationsCheckCell) view;
                        final RecyclerView.ViewHolder holder = this.listView.findViewHolderForAdapterPosition(position);
                        if (!enabled) {
                            getNotificationsController().setGlobalNotificationsEnabled(this.currentType, 0);
                            checkCell.setChecked(!enabled);
                            if (holder != null) {
                                this.adapter.onBindViewHolder(holder, position);
                            }
                            checkRowsEnabled();
                        } else {
                            AlertsCreator.showCustomNotificationsDialog(this, 0L, this.currentType, this.exceptions, this.currentAccount, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$QZxv9NWFXNvfRO-iiM7vm2RMU_s
                                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
                                public final void run(int i) {
                                    this.f$0.lambda$null$4$NotificationsCustomSettingsActivity(checkCell, holder, position, i);
                                }
                            });
                        }
                    } else if (position != this.previewRow) {
                        if (position == this.messageSoundRow) {
                            if (!view.isEnabled()) {
                                return;
                            }
                            try {
                                SharedPreferences preferences = getNotificationsSettings();
                                Intent tmpIntent = new Intent("android.intent.action.RINGTONE_PICKER");
                                tmpIntent.putExtra("android.intent.extra.ringtone.TYPE", 2);
                                tmpIntent.putExtra("android.intent.extra.ringtone.SHOW_DEFAULT", true);
                                tmpIntent.putExtra("android.intent.extra.ringtone.SHOW_SILENT", true);
                                tmpIntent.putExtra("android.intent.extra.ringtone.DEFAULT_URI", RingtoneManager.getDefaultUri(2));
                                Parcelable currentSound = null;
                                String defaultPath = null;
                                Uri defaultUri = Settings.System.DEFAULT_NOTIFICATION_URI;
                                if (defaultUri != null) {
                                    defaultPath = defaultUri.getPath();
                                }
                                if (this.currentType == 1) {
                                    path = preferences.getString("GlobalSoundPath", defaultPath);
                                } else if (this.currentType == 0) {
                                    path = preferences.getString("GroupSoundPath", defaultPath);
                                } else {
                                    path = preferences.getString("ChannelSoundPath", defaultPath);
                                }
                                if (path != null && !path.equals("NoSound")) {
                                    currentSound = path.equals(defaultPath) ? defaultUri : Uri.parse(path);
                                }
                                tmpIntent.putExtra("android.intent.extra.ringtone.EXISTING_URI", currentSound);
                                startActivityForResult(tmpIntent, position);
                            } catch (Exception e) {
                                FileLog.e(e);
                            }
                        } else if (position == this.messageLedRow) {
                            if (view.isEnabled()) {
                                showDialog(AlertsCreator.createColorSelectDialog(getParentActivity(), 0L, this.currentType, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$IoOWhVxMmwJBnAtcwA9Q9BPcnmk
                                    @Override // java.lang.Runnable
                                    public final void run() {
                                        this.f$0.lambda$null$5$NotificationsCustomSettingsActivity(position);
                                    }
                                }));
                            } else {
                                return;
                            }
                        } else if (position == this.messagePopupNotificationRow) {
                            if (view.isEnabled()) {
                                showDialog(AlertsCreator.createPopupSelectDialog(getParentActivity(), this.currentType, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$et6vdwXnURhZNNs0Lsi7fc_eQQw
                                    @Override // java.lang.Runnable
                                    public final void run() {
                                        this.f$0.lambda$null$6$NotificationsCustomSettingsActivity(position);
                                    }
                                }));
                            } else {
                                return;
                            }
                        } else if (position == this.messageVibrateRow) {
                            if (!view.isEnabled()) {
                                return;
                            }
                            int i = this.currentType;
                            if (i == 1) {
                                key = "vibrate_messages";
                            } else if (i == 0) {
                                key = "vibrate_group";
                            } else {
                                key = "vibrate_channel";
                            }
                            showDialog(AlertsCreator.createVibrationSelectDialog(getParentActivity(), 0L, key, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$IZIhKx_WNHVWkrCfIfrNBk6EXf0
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$null$7$NotificationsCustomSettingsActivity(position);
                                }
                            }));
                        } else if (position == this.messagePriorityRow) {
                            if (view.isEnabled()) {
                                showDialog(AlertsCreator.createPrioritySelectDialog(getParentActivity(), 0L, this.currentType, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$sZH1nKR4DN1AZlYJd-S0ELkdufw
                                    @Override // java.lang.Runnable
                                    public final void run() {
                                        this.f$0.lambda$null$8$NotificationsCustomSettingsActivity(position);
                                    }
                                }));
                            } else {
                                return;
                            }
                        }
                    } else {
                        if (!view.isEnabled()) {
                            return;
                        }
                        SharedPreferences preferences2 = getNotificationsSettings();
                        SharedPreferences.Editor editor = preferences2.edit();
                        int i2 = this.currentType;
                        if (i2 == 1) {
                            boolean enabled2 = preferences2.getBoolean("EnablePreviewAll", true);
                            editor.putBoolean("EnablePreviewAll", !enabled2);
                            enabled = enabled2;
                        } else if (i2 == 0) {
                            boolean enabled3 = preferences2.getBoolean("EnablePreviewGroup", true);
                            editor.putBoolean("EnablePreviewGroup", !enabled3);
                            enabled = enabled3;
                        } else {
                            boolean enabled4 = preferences2.getBoolean("EnablePreviewChannel", true);
                            editor.putBoolean("EnablePreviewChannel", !enabled4);
                            enabled = enabled4;
                        }
                        editor.commit();
                        getNotificationsController().updateServerNotificationsSettings(this.currentType);
                    }
                } else {
                    AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                    builder.setTitle(LocaleController.getString("NotificationsDeleteAllExceptionTitle", R.string.NotificationsDeleteAllExceptionTitle));
                    builder.setMessage(LocaleController.getString("NotificationsDeleteAllExceptionAlert", R.string.NotificationsDeleteAllExceptionAlert));
                    builder.setPositiveButton(LocaleController.getString("Delete", R.string.Delete), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$Vq_f5eL5WTeu0I3asm8WZ7iBbU4
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i3) {
                            this.f$0.lambda$null$3$NotificationsCustomSettingsActivity(dialogInterface, i3);
                        }
                    });
                    builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                    AlertDialog alertDialog = builder.create();
                    showDialog(alertDialog);
                    TextView button = (TextView) alertDialog.getButton(-1);
                    if (button != null) {
                        button.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
                    }
                }
            } else {
                Bundle args = new Bundle();
                args.putBoolean("onlySelect", true);
                args.putBoolean("checkCanWrite", false);
                int i3 = this.currentType;
                if (i3 == 0) {
                    args.putInt("dialogsType", 6);
                } else if (i3 == 2) {
                    args.putInt("dialogsType", 5);
                } else {
                    args.putInt("dialogsType", 4);
                }
                DialogsActivity activity = new DialogsActivity(args);
                activity.setDelegate(new DialogsActivity.DialogsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$9zCRP692iKdIq1FiobGn7zzsTIc
                    @Override // im.uwrkaxlmjj.ui.DialogsActivity.DialogsActivityDelegate
                    public final void didSelectDialogs(DialogsActivity dialogsActivity, ArrayList arrayList5, CharSequence charSequence, boolean z2) {
                        this.f$0.lambda$null$2$NotificationsCustomSettingsActivity(dialogsActivity, arrayList5, charSequence, z2);
                    }
                });
                presentFragment(activity);
            }
            if (view instanceof TextCheckCell) {
                ((TextCheckCell) view).setChecked(!enabled);
            }
        }
    }

    public /* synthetic */ void lambda$null$0$NotificationsCustomSettingsActivity(boolean newException, ArrayList arrayList, NotificationsSettingsActivity.NotificationException exception, int position, int param) {
        int idx;
        if (param == 0) {
            if (newException) {
                return;
            }
            ArrayList<NotificationsSettingsActivity.NotificationException> arrayList2 = this.exceptions;
            if (arrayList != arrayList2 && (idx = arrayList2.indexOf(exception)) >= 0) {
                this.exceptions.remove(idx);
                this.exceptionsDict.remove(Long.valueOf(exception.did));
            }
            arrayList.remove(exception);
            if (this.exceptionsAddRow != -1 && arrayList.isEmpty() && arrayList == this.exceptions) {
                this.listView.getAdapter().notifyItemChanged(this.exceptionsAddRow);
                this.listView.getAdapter().notifyItemRemoved(this.deleteAllRow);
                this.listView.getAdapter().notifyItemRemoved(this.deleteAllSectionRow);
            }
            this.listView.getAdapter().notifyItemRemoved(position);
            updateRows();
            checkRowsEnabled();
            this.actionBar.closeSearchField();
            return;
        }
        SharedPreferences preferences = getNotificationsSettings();
        exception.hasCustom = preferences.getBoolean(ContentMetadata.KEY_CUSTOM_PREFIX + exception.did, false);
        exception.notify = preferences.getInt("notify2_" + exception.did, 0);
        if (exception.notify != 0) {
            int time = preferences.getInt("notifyuntil_" + exception.did, -1);
            if (time != -1) {
                exception.muteUntil = time;
            }
        }
        if (newException) {
            this.exceptions.add(exception);
            this.exceptionsDict.put(Long.valueOf(exception.did), exception);
            updateRows();
            this.adapter.notifyDataSetChanged();
        } else {
            this.listView.getAdapter().notifyItemChanged(position);
        }
        this.actionBar.closeSearchField();
    }

    public /* synthetic */ void lambda$null$2$NotificationsCustomSettingsActivity(DialogsActivity fragment, ArrayList dids, CharSequence message, boolean param) {
        Bundle args2 = new Bundle();
        args2.putLong("dialog_id", ((Long) dids.get(0)).longValue());
        args2.putBoolean("exception", true);
        ProfileNotificationsActivity profileNotificationsActivity = new ProfileNotificationsActivity(args2);
        profileNotificationsActivity.setDelegate(new ProfileNotificationsActivity.ProfileNotificationsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$4X-QYH7frQHaU84KrScuPJBQ0vw
            @Override // im.uwrkaxlmjj.ui.ProfileNotificationsActivity.ProfileNotificationsActivityDelegate
            public final void didCreateNewException(NotificationsSettingsActivity.NotificationException notificationException) {
                this.f$0.lambda$null$1$NotificationsCustomSettingsActivity(notificationException);
            }
        });
        presentFragment(profileNotificationsActivity, true);
    }

    public /* synthetic */ void lambda$null$1$NotificationsCustomSettingsActivity(NotificationsSettingsActivity.NotificationException exception) {
        this.exceptions.add(0, exception);
        updateRows();
        this.adapter.notifyDataSetChanged();
    }

    public /* synthetic */ void lambda$null$3$NotificationsCustomSettingsActivity(DialogInterface dialogInterface, int i) {
        SharedPreferences preferences = getNotificationsSettings();
        SharedPreferences.Editor editor = preferences.edit();
        int N = this.exceptions.size();
        for (int a = 0; a < N; a++) {
            NotificationsSettingsActivity.NotificationException exception = this.exceptions.get(a);
            editor.remove("notify2_" + exception.did).remove(ContentMetadata.KEY_CUSTOM_PREFIX + exception.did);
            getMessagesStorage().setDialogFlags(exception.did, 0L);
            TLRPC.Dialog dialog = getMessagesController().dialogs_dict.get(exception.did);
            if (dialog != null) {
                dialog.notify_settings = new TLRPC.TL_peerNotifySettings();
            }
        }
        editor.commit();
        int N2 = this.exceptions.size();
        for (int a2 = 0; a2 < N2; a2++) {
            getNotificationsController().updateServerNotificationsSettings(this.exceptions.get(a2).did, false);
        }
        this.exceptions.clear();
        this.exceptionsDict.clear();
        updateRows();
        getNotificationCenter().postNotificationName(NotificationCenter.notificationsSettingsUpdated, new Object[0]);
        this.adapter.notifyDataSetChanged();
    }

    public /* synthetic */ void lambda$null$4$NotificationsCustomSettingsActivity(NotificationsCheckCell checkCell, RecyclerView.ViewHolder holder, int position, int param) {
        int offUntil;
        int iconType;
        SharedPreferences preferences = getNotificationsSettings();
        int offUntil2 = this.currentType;
        if (offUntil2 == 1) {
            offUntil = preferences.getInt("EnableAll2", 0);
        } else if (offUntil2 == 0) {
            offUntil = preferences.getInt("EnableGroup2", 0);
        } else {
            offUntil = preferences.getInt("EnableChannel2", 0);
        }
        int currentTime = getConnectionsManager().getCurrentTime();
        if (offUntil < currentTime || offUntil - 31536000 >= currentTime) {
            iconType = 0;
        } else {
            iconType = 2;
        }
        checkCell.setChecked(getNotificationsController().isGlobalNotificationsEnabled(this.currentType), iconType);
        if (holder != null) {
            this.adapter.onBindViewHolder(holder, position);
        }
        checkRowsEnabled();
    }

    public /* synthetic */ void lambda$null$5$NotificationsCustomSettingsActivity(int position) {
        RecyclerView.ViewHolder holder = this.listView.findViewHolderForAdapterPosition(position);
        if (holder != null) {
            this.adapter.onBindViewHolder(holder, position);
        }
    }

    public /* synthetic */ void lambda$null$6$NotificationsCustomSettingsActivity(int position) {
        RecyclerView.ViewHolder holder = this.listView.findViewHolderForAdapterPosition(position);
        if (holder != null) {
            this.adapter.onBindViewHolder(holder, position);
        }
    }

    public /* synthetic */ void lambda$null$7$NotificationsCustomSettingsActivity(int position) {
        RecyclerView.ViewHolder holder = this.listView.findViewHolderForAdapterPosition(position);
        if (holder != null) {
            this.adapter.onBindViewHolder(holder, position);
        }
    }

    public /* synthetic */ void lambda$null$8$NotificationsCustomSettingsActivity(int position) {
        RecyclerView.ViewHolder holder = this.listView.findViewHolderForAdapterPosition(position);
        if (holder != null) {
            this.adapter.onBindViewHolder(holder, position);
        }
    }

    private void checkRowsEnabled() {
        if (!this.exceptions.isEmpty()) {
            return;
        }
        int count = this.listView.getChildCount();
        ArrayList<Animator> animators = new ArrayList<>();
        boolean enabled = getNotificationsController().isGlobalNotificationsEnabled(this.currentType);
        for (int a = 0; a < count; a++) {
            View child = this.listView.getChildAt(a);
            RecyclerListView.Holder holder = (RecyclerListView.Holder) this.listView.getChildViewHolder(child);
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                HeaderCell headerCell = (HeaderCell) holder.itemView;
                if (holder.getAdapterPosition() == this.messageSectionRow) {
                    headerCell.setEnabled(enabled, animators);
                }
            } else if (itemViewType == 1) {
                TextCheckCell textCell = (TextCheckCell) holder.itemView;
                textCell.setEnabled(enabled, animators);
            } else if (itemViewType == 3) {
                TextColorCell textCell2 = (TextColorCell) holder.itemView;
                textCell2.setEnabled(enabled, animators);
            } else if (itemViewType == 5) {
                TextSettingsCell textCell3 = (TextSettingsCell) holder.itemView;
                textCell3.setEnabled(enabled, animators);
            }
        }
        if (!animators.isEmpty()) {
            AnimatorSet animatorSet = this.animatorSet;
            if (animatorSet != null) {
                animatorSet.cancel();
            }
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.animatorSet = animatorSet2;
            animatorSet2.playTogether(animators);
            this.animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.NotificationsCustomSettingsActivity.4
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animator) {
                    if (animator.equals(NotificationsCustomSettingsActivity.this.animatorSet)) {
                        NotificationsCustomSettingsActivity.this.animatorSet = null;
                    }
                }
            });
            this.animatorSet.setDuration(150L);
            this.animatorSet.start();
        }
    }

    private void loadExceptions() {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$Ha3Bn4t1g8ThpjL1unbkBDvG4CA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadExceptions$11$NotificationsCustomSettingsActivity();
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:117:0x02e6  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x0301 A[LOOP:3: B:123:0x02ff->B:124:0x0301, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:127:0x031a  */
    /* JADX WARN: Removed duplicated region for block: B:141:0x0254 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:80:0x026c  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0274 A[Catch: Exception -> 0x0287, TRY_LEAVE, TryCatch #2 {Exception -> 0x0287, blocks: (B:81:0x026e, B:83:0x0274), top: B:139:0x026e }] */
    /* JADX WARN: Removed duplicated region for block: B:89:0x0284  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x029a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$loadExceptions$11$NotificationsCustomSettingsActivity() {
        /*
            Method dump skipped, instruction units count: 860
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.NotificationsCustomSettingsActivity.lambda$loadExceptions$11$NotificationsCustomSettingsActivity():void");
    }

    public /* synthetic */ void lambda$null$10$NotificationsCustomSettingsActivity(ArrayList users, ArrayList chats, ArrayList encryptedChats, ArrayList usersResult, ArrayList chatsResult, ArrayList channelsResult) {
        getMessagesController().putUsers(users, true);
        getMessagesController().putChats(chats, true);
        getMessagesController().putEncryptedChats(encryptedChats, true);
        int i = this.currentType;
        if (i == 1) {
            this.exceptions = usersResult;
        } else if (i == 0) {
            this.exceptions = chatsResult;
        } else {
            this.exceptions = channelsResult;
        }
        updateRows();
        this.adapter.notifyDataSetChanged();
    }

    private void updateRows() {
        ArrayList<NotificationsSettingsActivity.NotificationException> arrayList;
        this.rowCount = 0;
        int i = this.currentType;
        if (i != -1) {
            int i2 = 0 + 1;
            this.rowCount = i2;
            this.alertRow = 0;
            int i3 = i2 + 1;
            this.rowCount = i3;
            this.alertSection2Row = i2;
            int i4 = i3 + 1;
            this.rowCount = i4;
            this.messageSectionRow = i3;
            int i5 = i4 + 1;
            this.rowCount = i5;
            this.previewRow = i4;
            int i6 = i5 + 1;
            this.rowCount = i6;
            this.messageLedRow = i5;
            int i7 = i6 + 1;
            this.rowCount = i7;
            this.messageVibrateRow = i6;
            if (i == 2) {
                this.messagePopupNotificationRow = -1;
            } else {
                this.rowCount = i7 + 1;
                this.messagePopupNotificationRow = i7;
            }
            int i8 = this.rowCount;
            this.rowCount = i8 + 1;
            this.messageSoundRow = i8;
            if (Build.VERSION.SDK_INT >= 21) {
                int i9 = this.rowCount;
                this.rowCount = i9 + 1;
                this.messagePriorityRow = i9;
            } else {
                this.messagePriorityRow = -1;
            }
            int i10 = this.rowCount;
            int i11 = i10 + 1;
            this.rowCount = i11;
            this.groupSection2Row = i10;
            this.rowCount = i11 + 1;
            this.exceptionsAddRow = i11;
        } else {
            this.alertRow = -1;
            this.alertSection2Row = -1;
            this.messageSectionRow = -1;
            this.previewRow = -1;
            this.messageLedRow = -1;
            this.messageVibrateRow = -1;
            this.messagePopupNotificationRow = -1;
            this.messageSoundRow = -1;
            this.messagePriorityRow = -1;
            this.groupSection2Row = -1;
            this.exceptionsAddRow = -1;
        }
        ArrayList<NotificationsSettingsActivity.NotificationException> arrayList2 = this.exceptions;
        if (arrayList2 != null && !arrayList2.isEmpty()) {
            int i12 = this.rowCount;
            this.exceptionsStartRow = i12;
            int size = i12 + this.exceptions.size();
            this.rowCount = size;
            this.exceptionsEndRow = size;
        } else {
            this.exceptionsStartRow = -1;
            this.exceptionsEndRow = -1;
        }
        if (this.currentType != -1 || ((arrayList = this.exceptions) != null && !arrayList.isEmpty())) {
            int i13 = this.rowCount;
            this.rowCount = i13 + 1;
            this.exceptionsSection2Row = i13;
        } else {
            this.exceptionsSection2Row = -1;
        }
        ArrayList<NotificationsSettingsActivity.NotificationException> arrayList3 = this.exceptions;
        if (arrayList3 != null && !arrayList3.isEmpty()) {
            int i14 = this.rowCount;
            int i15 = i14 + 1;
            this.rowCount = i15;
            this.deleteAllRow = i14;
            this.rowCount = i15 + 1;
            this.deleteAllSectionRow = i15;
            return;
        }
        this.deleteAllRow = -1;
        this.deleteAllSectionRow = -1;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        Ringtone rng;
        if (resultCode == -1) {
            Uri ringtone = (Uri) data.getParcelableExtra("android.intent.extra.ringtone.PICKED_URI");
            String name = null;
            if (ringtone != null && (rng = RingtoneManager.getRingtone(getParentActivity(), ringtone)) != null) {
                if (ringtone.equals(Settings.System.DEFAULT_NOTIFICATION_URI)) {
                    name = LocaleController.getString("SoundDefault", R.string.SoundDefault);
                } else {
                    name = rng.getTitle(getParentActivity());
                }
                rng.stop();
            }
            SharedPreferences preferences = getNotificationsSettings();
            SharedPreferences.Editor editor = preferences.edit();
            int i = this.currentType;
            if (i == 1) {
                if (name != null && ringtone != null) {
                    editor.putString("GlobalSound", name);
                    editor.putString("GlobalSoundPath", ringtone.toString());
                } else {
                    editor.putString("GlobalSound", "NoSound");
                    editor.putString("GlobalSoundPath", "NoSound");
                }
            } else if (i == 0) {
                if (name != null && ringtone != null) {
                    editor.putString("GroupSound", name);
                    editor.putString("GroupSoundPath", ringtone.toString());
                } else {
                    editor.putString("GroupSound", "NoSound");
                    editor.putString("GroupSoundPath", "NoSound");
                }
            } else if (i == 2) {
                if (name != null && ringtone != null) {
                    editor.putString("ChannelSound", name);
                    editor.putString("ChannelSoundPath", ringtone.toString());
                } else {
                    editor.putString("ChannelSound", "NoSound");
                    editor.putString("ChannelSoundPath", "NoSound");
                }
            }
            editor.commit();
            getNotificationsController().updateServerNotificationsSettings(this.currentType);
            RecyclerView.ViewHolder holder = this.listView.findViewHolderForAdapterPosition(requestCode);
            if (holder != null) {
                this.adapter.onBindViewHolder(holder, requestCode);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.adapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class SearchAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;
        private SearchAdapterHelper searchAdapterHelper;
        private ArrayList<NotificationsSettingsActivity.NotificationException> searchResult = new ArrayList<>();
        private ArrayList<CharSequence> searchResultNames = new ArrayList<>();
        private Runnable searchRunnable;

        public SearchAdapter(Context context) {
            this.mContext = context;
            SearchAdapterHelper searchAdapterHelper = new SearchAdapterHelper(true);
            this.searchAdapterHelper = searchAdapterHelper;
            searchAdapterHelper.setDelegate(new SearchAdapterHelper.SearchAdapterHelperDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$SearchAdapter$AKVNr9y98EMjcIcCdVCW3FWk12M
                @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
                public /* synthetic */ SparseArray<TLRPC.User> getExcludeUsers() {
                    return SearchAdapterHelper.SearchAdapterHelperDelegate.CC.$default$getExcludeUsers(this);
                }

                @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
                public final void onDataSetChanged() {
                    this.f$0.lambda$new$0$NotificationsCustomSettingsActivity$SearchAdapter();
                }

                @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
                public /* synthetic */ void onSetHashtags(ArrayList<SearchAdapterHelper.HashtagObject> arrayList, HashMap<String, SearchAdapterHelper.HashtagObject> map) {
                    SearchAdapterHelper.SearchAdapterHelperDelegate.CC.$default$onSetHashtags(this, arrayList, map);
                }
            });
        }

        public /* synthetic */ void lambda$new$0$NotificationsCustomSettingsActivity$SearchAdapter() {
            if (this.searchRunnable == null && !this.searchAdapterHelper.isSearchInProgress()) {
                NotificationsCustomSettingsActivity.this.emptyView.showTextView();
            }
            notifyDataSetChanged();
        }

        public void searchDialogs(final String query) {
            if (this.searchRunnable != null) {
                Utilities.searchQueue.cancelRunnable(this.searchRunnable);
                this.searchRunnable = null;
            }
            if (query == null) {
                this.searchResult.clear();
                this.searchResultNames.clear();
                this.searchAdapterHelper.mergeResults(null);
                this.searchAdapterHelper.queryServerSearch(null, true, NotificationsCustomSettingsActivity.this.currentType != 1, true, false, 0, false, 0);
                notifyDataSetChanged();
                return;
            }
            DispatchQueue dispatchQueue = Utilities.searchQueue;
            Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$SearchAdapter$E6a-RweF4TpxI5nQ8a8dq2jC-XY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$searchDialogs$1$NotificationsCustomSettingsActivity$SearchAdapter(query);
                }
            };
            this.searchRunnable = runnable;
            dispatchQueue.postRunnable(runnable, 300L);
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* JADX INFO: renamed from: processSearch, reason: merged with bridge method [inline-methods] */
        public void lambda$searchDialogs$1$NotificationsCustomSettingsActivity$SearchAdapter(final String query) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$SearchAdapter$DHN-iJEitShyF0eK7067zmk-WGE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$processSearch$3$NotificationsCustomSettingsActivity$SearchAdapter(query);
                }
            });
        }

        public /* synthetic */ void lambda$processSearch$3$NotificationsCustomSettingsActivity$SearchAdapter(final String query) {
            this.searchAdapterHelper.queryServerSearch(query, true, NotificationsCustomSettingsActivity.this.currentType != 1, true, false, 0, false, 0);
            final ArrayList<NotificationsSettingsActivity.NotificationException> contactsCopy = new ArrayList<>(NotificationsCustomSettingsActivity.this.exceptions);
            Utilities.searchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$SearchAdapter$E8O4Up0WoTZCU8dE97cXSE3QMT0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$2$NotificationsCustomSettingsActivity$SearchAdapter(query, contactsCopy);
                }
            });
        }

        /* JADX WARN: Removed duplicated region for block: B:100:0x01ce A[SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:88:0x0215 A[LOOP:1: B:57:0x0163->B:88:0x0215, LOOP_END] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public /* synthetic */ void lambda$null$2$NotificationsCustomSettingsActivity$SearchAdapter(java.lang.String r26, java.util.ArrayList r27) {
            /*
                Method dump skipped, instruction units count: 579
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.NotificationsCustomSettingsActivity.SearchAdapter.lambda$null$2$NotificationsCustomSettingsActivity$SearchAdapter(java.lang.String, java.util.ArrayList):void");
        }

        private void updateSearchResults(final ArrayList<TLObject> result, final ArrayList<NotificationsSettingsActivity.NotificationException> exceptions, final ArrayList<CharSequence> names) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$SearchAdapter$aGlk5RPumBG7GKIw2ZZXDwZkw3M
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$updateSearchResults$4$NotificationsCustomSettingsActivity$SearchAdapter(exceptions, names, result);
                }
            });
        }

        public /* synthetic */ void lambda$updateSearchResults$4$NotificationsCustomSettingsActivity$SearchAdapter(ArrayList exceptions, ArrayList names, ArrayList result) {
            this.searchRunnable = null;
            this.searchResult = exceptions;
            this.searchResultNames = names;
            this.searchAdapterHelper.mergeResults(result);
            if (NotificationsCustomSettingsActivity.this.searching && !this.searchAdapterHelper.isSearchInProgress()) {
                NotificationsCustomSettingsActivity.this.emptyView.showTextView();
            }
            notifyDataSetChanged();
        }

        public Object getObject(int position) {
            if (position >= 0 && position < this.searchResult.size()) {
                return this.searchResult.get(position);
            }
            int position2 = position - (this.searchResult.size() + 1);
            ArrayList<TLObject> globalSearch = this.searchAdapterHelper.getGlobalSearch();
            if (position2 >= 0 && position2 < globalSearch.size()) {
                return this.searchAdapterHelper.getGlobalSearch().get(position2);
            }
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int count = this.searchResult.size();
            ArrayList<TLObject> globalSearch = this.searchAdapterHelper.getGlobalSearch();
            if (!globalSearch.isEmpty()) {
                return count + globalSearch.size() + 1;
            }
            return count;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new UserCell(this.mContext, 4, 0, false, true);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else {
                view = new GraySectionCell(this.mContext);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType == 1) {
                    ((GraySectionCell) holder.itemView).setText(LocaleController.getString("AddToExceptions", R.string.AddToExceptions));
                    return;
                }
                return;
            }
            UserCell cell = (UserCell) holder.itemView;
            if (position < this.searchResult.size()) {
                cell.setException(this.searchResult.get(position), this.searchResultNames.get(position), position != this.searchResult.size() - 1);
                cell.setAddButtonVisible(false);
                return;
            }
            int position2 = position - (this.searchResult.size() + 1);
            ArrayList<TLObject> globalSearch = this.searchAdapterHelper.getGlobalSearch();
            TLObject object = globalSearch.get(position2);
            cell.setData(object, null, LocaleController.getString("NotificationsOn", R.string.NotificationsOn), 0, position2 != globalSearch.size() - 1);
            cell.setAddButtonVisible(true);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == this.searchResult.size()) {
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
            int type = holder.getItemViewType();
            return (type == 0 || type == 4) ? false : true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return NotificationsCustomSettingsActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            switch (viewType) {
                case 0:
                    view = new HeaderCell(this.mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 1:
                    view = new TextCheckCell(this.mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 2:
                    view = new UserCell(this.mContext, 6, 0, false);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 3:
                    view = new TextColorCell(this.mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 4:
                    view = new ShadowSectionCell(this.mContext);
                    break;
                case 5:
                    view = new TextSettingsCell(this.mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 6:
                    view = new NotificationsCheckCell(this.mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                default:
                    view = new TextCell(this.mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            boolean enabled;
            int color;
            int option;
            String value;
            int value2;
            int value3;
            String value4;
            String text;
            int offUntil;
            int iconType;
            switch (holder.getItemViewType()) {
                case 0:
                    HeaderCell headerCell = (HeaderCell) holder.itemView;
                    if (position == NotificationsCustomSettingsActivity.this.messageSectionRow) {
                        headerCell.setText(LocaleController.getString("SETTINGS", R.string.SETTINGS));
                    }
                    break;
                case 1:
                    TextCheckCell checkCell = (TextCheckCell) holder.itemView;
                    SharedPreferences preferences = NotificationsCustomSettingsActivity.this.getNotificationsSettings();
                    if (position == NotificationsCustomSettingsActivity.this.previewRow) {
                        if (NotificationsCustomSettingsActivity.this.currentType != 1) {
                            if (NotificationsCustomSettingsActivity.this.currentType == 0) {
                                enabled = preferences.getBoolean("EnablePreviewGroup", true);
                            } else {
                                enabled = preferences.getBoolean("EnablePreviewChannel", true);
                            }
                        } else {
                            enabled = preferences.getBoolean("EnablePreviewAll", true);
                        }
                        checkCell.setTextAndCheck(LocaleController.getString("MessagePreview", R.string.MessagePreview), enabled, true);
                    }
                    break;
                case 2:
                    UserCell cell = (UserCell) holder.itemView;
                    NotificationsSettingsActivity.NotificationException exception = (NotificationsSettingsActivity.NotificationException) NotificationsCustomSettingsActivity.this.exceptions.get(position - NotificationsCustomSettingsActivity.this.exceptionsStartRow);
                    cell.setException(exception, null, position != NotificationsCustomSettingsActivity.this.exceptionsEndRow - 1);
                    break;
                case 3:
                    TextColorCell textColorCell = (TextColorCell) holder.itemView;
                    SharedPreferences preferences2 = NotificationsCustomSettingsActivity.this.getNotificationsSettings();
                    if (NotificationsCustomSettingsActivity.this.currentType != 1) {
                        if (NotificationsCustomSettingsActivity.this.currentType == 0) {
                            color = preferences2.getInt("GroupLed", -16776961);
                        } else {
                            color = preferences2.getInt("ChannelLed", -16776961);
                        }
                    } else {
                        color = preferences2.getInt("MessagesLed", -16776961);
                    }
                    int a = 0;
                    while (true) {
                        if (a < 9) {
                            if (TextColorCell.colorsToSave[a] != color) {
                                a++;
                            } else {
                                color = TextColorCell.colors[a];
                            }
                        }
                    }
                    textColorCell.setTextAndColor(LocaleController.getString("LedColor", R.string.LedColor), color, true);
                    break;
                case 4:
                    if (position == NotificationsCustomSettingsActivity.this.deleteAllSectionRow || ((position == NotificationsCustomSettingsActivity.this.groupSection2Row && NotificationsCustomSettingsActivity.this.exceptionsSection2Row == -1) || (position == NotificationsCustomSettingsActivity.this.exceptionsSection2Row && NotificationsCustomSettingsActivity.this.deleteAllRow == -1))) {
                        holder.itemView.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                    } else {
                        holder.itemView.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                    }
                    break;
                case 5:
                    TextSettingsCell textCell = (TextSettingsCell) holder.itemView;
                    SharedPreferences preferences3 = NotificationsCustomSettingsActivity.this.getNotificationsSettings();
                    if (position == NotificationsCustomSettingsActivity.this.messageSoundRow) {
                        if (NotificationsCustomSettingsActivity.this.currentType != 1) {
                            if (NotificationsCustomSettingsActivity.this.currentType == 0) {
                                value4 = preferences3.getString("GroupSound", LocaleController.getString("SoundDefault", R.string.SoundDefault));
                            } else {
                                String value5 = LocaleController.getString("SoundDefault", R.string.SoundDefault);
                                value4 = preferences3.getString("ChannelSound", value5);
                            }
                        } else {
                            value4 = preferences3.getString("GlobalSound", LocaleController.getString("SoundDefault", R.string.SoundDefault));
                        }
                        if (value4.equals("NoSound")) {
                            value4 = LocaleController.getString("NoSound", R.string.NoSound);
                        }
                        textCell.setTextAndValue(LocaleController.getString("Sound", R.string.Sound), value4, true);
                    } else if (position == NotificationsCustomSettingsActivity.this.messageVibrateRow) {
                        if (NotificationsCustomSettingsActivity.this.currentType != 1) {
                            if (NotificationsCustomSettingsActivity.this.currentType == 0) {
                                value3 = preferences3.getInt("vibrate_group", 0);
                            } else {
                                value3 = preferences3.getInt("vibrate_channel", 0);
                            }
                        } else {
                            value3 = preferences3.getInt("vibrate_messages", 0);
                        }
                        if (value3 == 0) {
                            textCell.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("VibrationDefault", R.string.VibrationDefault), true);
                        } else if (value3 == 1) {
                            textCell.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("Short", R.string.Short), true);
                        } else if (value3 == 2) {
                            textCell.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("VibrationDisabled", R.string.VibrationDisabled), true);
                        } else if (value3 == 3) {
                            textCell.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("Long", R.string.Long), true);
                        } else if (value3 == 4) {
                            textCell.setTextAndValue(LocaleController.getString("Vibrate", R.string.Vibrate), LocaleController.getString("OnlyIfSilent", R.string.OnlyIfSilent), true);
                        }
                    } else if (position == NotificationsCustomSettingsActivity.this.messagePriorityRow) {
                        if (NotificationsCustomSettingsActivity.this.currentType != 1) {
                            if (NotificationsCustomSettingsActivity.this.currentType == 0) {
                                value2 = preferences3.getInt("priority_group", 1);
                            } else {
                                value2 = preferences3.getInt("priority_channel", 1);
                            }
                        } else {
                            value2 = preferences3.getInt("priority_messages", 1);
                        }
                        if (value2 == 0) {
                            textCell.setTextAndValue(LocaleController.getString("NotificationsImportance", R.string.NotificationsImportance), LocaleController.getString("NotificationsPriorityHigh", R.string.NotificationsPriorityHigh), true);
                        } else if (value2 == 1 || value2 == 2) {
                            textCell.setTextAndValue(LocaleController.getString("NotificationsImportance", R.string.NotificationsImportance), LocaleController.getString("NotificationsPriorityUrgent", R.string.NotificationsPriorityUrgent), true);
                        } else if (value2 == 4) {
                            textCell.setTextAndValue(LocaleController.getString("NotificationsImportance", R.string.NotificationsImportance), LocaleController.getString("NotificationsPriorityLow", R.string.NotificationsPriorityLow), true);
                        } else if (value2 == 5) {
                            textCell.setTextAndValue(LocaleController.getString("NotificationsImportance", R.string.NotificationsImportance), LocaleController.getString("NotificationsPriorityMedium", R.string.NotificationsPriorityMedium), true);
                        }
                    } else if (position == NotificationsCustomSettingsActivity.this.messagePopupNotificationRow) {
                        if (NotificationsCustomSettingsActivity.this.currentType != 1) {
                            if (NotificationsCustomSettingsActivity.this.currentType == 0) {
                                option = preferences3.getInt("popupGroup", 0);
                            } else {
                                option = preferences3.getInt("popupChannel", 0);
                            }
                        } else {
                            option = preferences3.getInt("popupAll", 0);
                        }
                        if (option == 0) {
                            value = LocaleController.getString("NoPopup", R.string.NoPopup);
                        } else if (option == 1) {
                            value = LocaleController.getString("OnlyWhenScreenOn", R.string.OnlyWhenScreenOn);
                        } else if (option == 2) {
                            value = LocaleController.getString("OnlyWhenScreenOff", R.string.OnlyWhenScreenOff);
                        } else {
                            value = LocaleController.getString("AlwaysShowPopup", R.string.AlwaysShowPopup);
                        }
                        textCell.setTextAndValue(LocaleController.getString("PopupNotification", R.string.PopupNotification), value, true);
                    }
                    break;
                case 6:
                    NotificationsCheckCell checkCell2 = (NotificationsCheckCell) holder.itemView;
                    checkCell2.setDrawLine(false);
                    StringBuilder builder = new StringBuilder();
                    SharedPreferences preferences4 = NotificationsCustomSettingsActivity.this.getNotificationsSettings();
                    if (NotificationsCustomSettingsActivity.this.currentType != 1) {
                        if (NotificationsCustomSettingsActivity.this.currentType == 0) {
                            String text2 = LocaleController.getString("NotificationsForGroups", R.string.NotificationsForGroups);
                            text = text2;
                            offUntil = preferences4.getInt("EnableGroup2", 0);
                        } else {
                            String text3 = LocaleController.getString("NotificationsForChannels", R.string.NotificationsForChannels);
                            text = text3;
                            offUntil = preferences4.getInt("EnableChannel2", 0);
                        }
                    } else {
                        String text4 = LocaleController.getString("NotificationsForPrivateChats", R.string.NotificationsForPrivateChats);
                        text = text4;
                        offUntil = preferences4.getInt("EnableAll2", 0);
                    }
                    int currentTime = NotificationsCustomSettingsActivity.this.getConnectionsManager().getCurrentTime();
                    boolean z = offUntil < currentTime;
                    boolean enabled2 = z;
                    if (z) {
                        builder.append(LocaleController.getString("NotificationsOn", R.string.NotificationsOn));
                        iconType = 0;
                    } else if (offUntil - 31536000 >= currentTime) {
                        builder.append(LocaleController.getString("NotificationsOff", R.string.NotificationsOff));
                        iconType = 0;
                    } else {
                        builder.append(LocaleController.formatString("NotificationsOffUntil", R.string.NotificationsOffUntil, LocaleController.stringForMessageListDate(offUntil)));
                        iconType = 2;
                    }
                    checkCell2.setTextAndValueAndCheck(text, builder, enabled2, iconType, false);
                    break;
                case 7:
                    TextCell textCell2 = (TextCell) holder.itemView;
                    if (position == NotificationsCustomSettingsActivity.this.exceptionsAddRow) {
                        textCell2.setTextAndIcon(LocaleController.getString("NotificationsAddAnException", R.string.NotificationsAddAnException), R.drawable.actions_addmember2, NotificationsCustomSettingsActivity.this.exceptionsStartRow != -1);
                        textCell2.setColors(Theme.key_windowBackgroundWhiteBlueIcon, Theme.key_windowBackgroundWhiteBlueButton);
                    } else if (position == NotificationsCustomSettingsActivity.this.deleteAllRow) {
                        textCell2.setText(LocaleController.getString("NotificationsDeleteAllException", R.string.NotificationsDeleteAllException), false);
                        textCell2.setColors(null, Theme.key_windowBackgroundWhiteRedText5);
                    }
                    break;
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewAttachedToWindow(RecyclerView.ViewHolder holder) {
            if (NotificationsCustomSettingsActivity.this.exceptions != null && NotificationsCustomSettingsActivity.this.exceptions.isEmpty()) {
                boolean enabled = NotificationsCustomSettingsActivity.this.getNotificationsController().isGlobalNotificationsEnabled(NotificationsCustomSettingsActivity.this.currentType);
                int itemViewType = holder.getItemViewType();
                if (itemViewType == 0) {
                    HeaderCell headerCell = (HeaderCell) holder.itemView;
                    if (holder.getAdapterPosition() == NotificationsCustomSettingsActivity.this.messageSectionRow) {
                        headerCell.setEnabled(enabled, null);
                        return;
                    } else {
                        headerCell.setEnabled(true, null);
                        return;
                    }
                }
                if (itemViewType == 1) {
                    TextCheckCell textCell = (TextCheckCell) holder.itemView;
                    textCell.setEnabled(enabled, null);
                } else if (itemViewType == 3) {
                    TextColorCell textCell2 = (TextColorCell) holder.itemView;
                    textCell2.setEnabled(enabled, null);
                } else if (itemViewType == 5) {
                    TextSettingsCell textCell3 = (TextSettingsCell) holder.itemView;
                    textCell3.setEnabled(enabled, null);
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != NotificationsCustomSettingsActivity.this.messageSectionRow) {
                if (position != NotificationsCustomSettingsActivity.this.previewRow) {
                    if (position < NotificationsCustomSettingsActivity.this.exceptionsStartRow || position >= NotificationsCustomSettingsActivity.this.exceptionsEndRow) {
                        if (position != NotificationsCustomSettingsActivity.this.messageLedRow) {
                            if (position != NotificationsCustomSettingsActivity.this.groupSection2Row && position != NotificationsCustomSettingsActivity.this.alertSection2Row && position != NotificationsCustomSettingsActivity.this.exceptionsSection2Row && position != NotificationsCustomSettingsActivity.this.deleteAllSectionRow) {
                                if (position != NotificationsCustomSettingsActivity.this.alertRow) {
                                    if (position == NotificationsCustomSettingsActivity.this.exceptionsAddRow || position == NotificationsCustomSettingsActivity.this.deleteAllRow) {
                                        return 7;
                                    }
                                    return 5;
                                }
                                return 6;
                            }
                            return 4;
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
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NotificationsCustomSettingsActivity$3LpA6U05rImJ6Ni6XFLplGAVpBw
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$12$NotificationsCustomSettingsActivity();
            }
        };
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{HeaderCell.class, TextCheckCell.class, TextColorCell.class, TextSettingsCell.class, UserCell.class, NotificationsCheckCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrack), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackChecked), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"statusColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteGrayText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"statusOnlineColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteBlueText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink), new ThemeDescription(this.listView, 0, new Class[]{GraySectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_graySectionText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{GraySectionCell.class}, null, null, null, Theme.key_graySection), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrack), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackChecked), new ThemeDescription(this.listView, 0, new Class[]{TextColorCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueButton), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteRedText5), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{TextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueIcon)};
    }

    public /* synthetic */ void lambda$getThemeDescriptions$12$NotificationsCustomSettingsActivity() {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            int count = recyclerListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.listView.getChildAt(a);
                if (child instanceof UserCell) {
                    ((UserCell) child).update(0);
                }
            }
        }
    }
}
