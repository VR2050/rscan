package im.uwrkaxlmjj.ui.hui.mine;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.CheckBoxCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.SessionCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.mine.MrySessionsActivity;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MrySessionsActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private TLRPC.TL_authorization currentSession;
    private int currentSessionRow;
    private int currentSessionSectionRow;
    private int currentType;
    private LinearLayout emptyLayout;
    private EmptyTextProgressView emptyView;
    private ImageView imageView;
    private ListAdapter listAdapter;
    private SlidingItemMenuRecyclerView listView;
    private boolean loading;
    private Context mContext;
    private int noOtherSessionsRow;
    private int otherSessionsEndRow;
    private int otherSessionsSectionRow;
    private int otherSessionsStartRow;
    private int otherSessionsTerminateDetail;
    private int passwordSessionsDetailRow;
    private int passwordSessionsEndRow;
    private int passwordSessionsSectionRow;
    private int passwordSessionsStartRow;
    private int rowCount;
    private int terminateAllSessionsDetailRow;
    private int terminateAllSessionsRow;
    private TextView textView1;
    private TextView textView2;
    private ArrayList<TLObject> sessions = new ArrayList<>();
    private ArrayList<TLObject> passwordSessions = new ArrayList<>();

    public MrySessionsActivity(int type) {
        this.currentType = type;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        updateRows();
        loadSessions(false);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.newSessionReceived);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.newSessionReceived);
    }

    private void initActionBar() {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        if (this.currentType == 0) {
            this.actionBar.setTitle(LocaleController.getString("SessionsTitle", R.string.SessionsTitle));
        } else {
            this.actionBar.setTitle(LocaleController.getString("WebSessionsTitle", R.string.WebSessionsTitle));
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.mine.MrySessionsActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    MrySessionsActivity.this.finishFragment();
                }
            }
        });
    }

    private void initList() {
        this.listView = (SlidingItemMenuRecyclerView) this.fragmentView.findViewById(R.attr.listview);
        this.listAdapter = new ListAdapter(this.mContext);
        this.listView.setLayoutManager(new LinearLayoutManager(this.mContext, 1, false));
        this.listView.setHasFixedSize(true);
        this.listView.setNestedScrollingEnabled(false);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setEmptyView(this.emptyView);
        this.listView.setAdapter(this.listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$ll0Aqs-_zBfnZFdbPDCKpNa4EQ4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$5$MrySessionsActivity(view, i);
            }
        });
    }

    public /* synthetic */ void lambda$initList$5$MrySessionsActivity(View view, int position) {
        if (position != this.terminateAllSessionsRow || getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        if (this.currentType == 0) {
            builder.setMessage(LocaleController.getString("AreYouSureSessions", R.string.AreYouSureSessions));
        } else {
            builder.setMessage(LocaleController.getString("AreYouSureWebSessions", R.string.AreYouSureWebSessions));
        }
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$aRdG1idguaqakF-H4eoZAv1QlQA
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$4$MrySessionsActivity(dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$null$4$MrySessionsActivity(DialogInterface dialogInterface, int i) {
        if (this.currentType == 0) {
            TLRPC.TL_auth_resetAuthorizations req = new TLRPC.TL_auth_resetAuthorizations();
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$pxPj_gRzCZ289IoV9ia0jelXBYA
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$1$MrySessionsActivity(tLObject, tL_error);
                }
            });
        } else {
            TLRPC.TL_account_resetWebAuthorizations req2 = new TLRPC.TL_account_resetWebAuthorizations();
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$DxO7GXWeepCiOyiOinwEp5lgF7o
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$3$MrySessionsActivity(tLObject, tL_error);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$1$MrySessionsActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$FvLxgB_tZn6jJMo5KeH89p2BlVU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$MrySessionsActivity(error, response);
            }
        });
        for (int a = 0; a < 3; a++) {
            UserConfig userConfig = UserConfig.getInstance(a);
            if (userConfig.isClientActivated()) {
                userConfig.registeredForPush = false;
                userConfig.saveConfig(false);
                MessagesController.getInstance(a).registerForPush(SharedConfig.pushString);
                ConnectionsManager.getInstance(a).setUserId(userConfig.getClientUserId());
            }
        }
    }

    public /* synthetic */ void lambda$null$0$MrySessionsActivity(TLRPC.TL_error error, TLObject response) {
        if (getParentActivity() != null && error == null && (response instanceof TLRPC.TL_boolTrue)) {
            ToastUtils.show(R.string.TerminateAllSessions);
            finishFragment();
        }
    }

    public /* synthetic */ void lambda$null$3$MrySessionsActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$9o39oMWvZtNjCrQ89-wImlLCS1A
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$MrySessionsActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$MrySessionsActivity(TLRPC.TL_error error, TLObject response) {
        if (getParentActivity() == null) {
            return;
        }
        if (error == null && (response instanceof TLRPC.TL_boolTrue)) {
            ToastUtils.show(R.string.TerminateAllWebSessions);
        } else {
            ToastUtils.show(R.string.UnknownError);
        }
        finishFragment();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_slide_listview_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initActionBar();
        initList();
        LinearLayout linearLayout = new LinearLayout(context);
        this.emptyLayout = linearLayout;
        linearLayout.setOrientation(1);
        this.emptyLayout.setGravity(17);
        this.emptyLayout.setLayoutParams(new AbsListView.LayoutParams(-1, AndroidUtilities.displaySize.y - ActionBar.getCurrentActionBarHeight()));
        ImageView imageView = new ImageView(context);
        this.imageView = imageView;
        if (this.currentType == 0) {
            imageView.setImageResource(R.drawable.devices);
        } else {
            imageView.setImageResource(R.drawable.no_apps);
        }
        this.imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_sessions_devicesImage), PorterDuff.Mode.MULTIPLY));
        this.emptyLayout.addView(this.imageView, LayoutHelper.createLinear(-2, -2));
        TextView textView = new TextView(context);
        this.textView1 = textView;
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
        this.textView1.setGravity(17);
        this.textView1.setTextSize(1, 15.0f);
        this.textView1.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        if (this.currentType == 0) {
            this.textView1.setText(LocaleController.getString("NoOtherSessions", R.string.NoOtherSessions));
        } else {
            this.textView1.setText(LocaleController.getString("NoOtherWebSessions", R.string.NoOtherWebSessions));
        }
        this.emptyLayout.addView(this.textView1, LayoutHelper.createLinear(-2, -2, 17, 0, 16, 0, 0));
        TextView textView2 = new TextView(context);
        this.textView2 = textView2;
        textView2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
        this.textView2.setGravity(17);
        this.textView2.setTextSize(1, 14.0f);
        this.textView2.setPadding(AndroidUtilities.dp(20.0f), 0, AndroidUtilities.dp(20.0f), 0);
        if (this.currentType == 0) {
            this.textView2.setText(LocaleController.getString("NoOtherSessionsInfo", R.string.NoOtherSessionsInfo));
        } else {
            this.textView2.setText(LocaleController.getString("NoOtherWebSessionsInfo", R.string.NoOtherWebSessionsInfo));
        }
        this.emptyLayout.addView(this.textView2, LayoutHelper.createLinear(-2, -2, 17, 0, 14, 0, 0));
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.emptyView = emptyTextProgressView;
        emptyTextProgressView.showProgress();
        return this.fragmentView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.newSessionReceived) {
            loadSessions(true);
        }
    }

    private void loadSessions(boolean silent) {
        if (this.loading) {
            return;
        }
        if (!silent) {
            this.loading = true;
        }
        if (this.currentType == 0) {
            TLRPC.TL_account_getAuthorizations req = new TLRPC.TL_account_getAuthorizations();
            int reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$8qJm111NQjEVDNXla8G7TSzTLPk
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$loadSessions$7$MrySessionsActivity(tLObject, tL_error);
                }
            });
            ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(reqId, this.classGuid);
        } else {
            TLRPC.TL_account_getWebAuthorizations req2 = new TLRPC.TL_account_getWebAuthorizations();
            int reqId2 = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$DnDCXEC-D1Q7ixyffyfv1BlNI8o
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$loadSessions$9$MrySessionsActivity(tLObject, tL_error);
                }
            });
            ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(reqId2, this.classGuid);
        }
    }

    public /* synthetic */ void lambda$loadSessions$7$MrySessionsActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$GLr5BBDf6ry5gmO0Pcw8vnEJzEQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$6$MrySessionsActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$6$MrySessionsActivity(TLRPC.TL_error error, TLObject response) {
        this.loading = false;
        if (error == null) {
            this.sessions.clear();
            this.passwordSessions.clear();
            TLRPC.TL_account_authorizations res = (TLRPC.TL_account_authorizations) response;
            int N = res.authorizations.size();
            for (int a = 0; a < N; a++) {
                TLRPC.TL_authorization authorization = res.authorizations.get(a);
                if ((authorization.flags & 1) != 0) {
                    this.currentSession = authorization;
                } else if (authorization.password_pending) {
                    this.passwordSessions.add(authorization);
                } else {
                    this.sessions.add(authorization);
                }
            }
            updateRows();
        }
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    public /* synthetic */ void lambda$loadSessions$9$MrySessionsActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$mV9aU_WQACT6Xtz6LEOs76JloKo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$8$MrySessionsActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$8$MrySessionsActivity(TLRPC.TL_error error, TLObject response) {
        this.loading = false;
        if (error == null) {
            this.sessions.clear();
            TLRPC.TL_account_webAuthorizations res = (TLRPC.TL_account_webAuthorizations) response;
            MessagesController.getInstance(this.currentAccount).putUsers(res.users, false);
            this.sessions.addAll(res.authorizations);
            updateRows();
        }
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateRows() {
        this.rowCount = 0;
        if (this.currentSession != null) {
            int i = 0 + 1;
            this.rowCount = i;
            this.currentSessionSectionRow = 0;
            this.rowCount = i + 1;
            this.currentSessionRow = i;
        } else {
            this.currentSessionRow = -1;
            this.currentSessionSectionRow = -1;
        }
        if (!this.passwordSessions.isEmpty() || !this.sessions.isEmpty()) {
            int i2 = this.rowCount;
            int i3 = i2 + 1;
            this.rowCount = i3;
            this.terminateAllSessionsRow = i2;
            this.rowCount = i3 + 1;
            this.terminateAllSessionsDetailRow = i3;
            this.noOtherSessionsRow = -1;
        } else {
            this.terminateAllSessionsRow = -1;
            this.terminateAllSessionsDetailRow = -1;
            if (this.currentType == 1 || this.currentSession != null) {
                int i4 = this.rowCount;
                this.rowCount = i4 + 1;
                this.noOtherSessionsRow = i4;
            } else {
                this.noOtherSessionsRow = -1;
            }
        }
        if (this.passwordSessions.isEmpty()) {
            this.passwordSessionsDetailRow = -1;
            this.passwordSessionsEndRow = -1;
            this.passwordSessionsStartRow = -1;
            this.passwordSessionsSectionRow = -1;
        } else {
            int i5 = this.rowCount;
            int i6 = i5 + 1;
            this.rowCount = i6;
            this.passwordSessionsSectionRow = i5;
            this.passwordSessionsStartRow = i6;
            int size = i6 + this.passwordSessions.size();
            this.rowCount = size;
            this.passwordSessionsEndRow = size;
            this.rowCount = size + 1;
            this.passwordSessionsDetailRow = size;
        }
        if (this.sessions.isEmpty()) {
            this.otherSessionsSectionRow = -1;
            this.otherSessionsStartRow = -1;
            this.otherSessionsEndRow = -1;
            this.otherSessionsTerminateDetail = -1;
            return;
        }
        int i7 = this.rowCount;
        this.rowCount = i7 + 1;
        this.otherSessionsSectionRow = i7;
        int i8 = i7 + 1;
        this.otherSessionsStartRow = i8;
        this.otherSessionsEndRow = i8 + this.sessions.size();
        int size2 = this.rowCount + this.sessions.size();
        this.rowCount = size2;
        this.rowCount = size2 + 1;
        this.otherSessionsTerminateDetail = size2;
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return position == MrySessionsActivity.this.terminateAllSessionsRow || (position >= MrySessionsActivity.this.otherSessionsStartRow && position < MrySessionsActivity.this.otherSessionsEndRow) || (position >= MrySessionsActivity.this.passwordSessionsStartRow && position < MrySessionsActivity.this.passwordSessionsEndRow);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (MrySessionsActivity.this.loading) {
                return 0;
            }
            return MrySessionsActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                View view2 = new TextSettingsCell(this.mContext);
                view2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view = view2;
            } else if (viewType == 1 || viewType == 2) {
                view = new TextInfoPrivacyCell(this.mContext);
            } else if (viewType == 3) {
                view = MrySessionsActivity.this.emptyLayout;
            } else if (viewType == 5) {
                View view3 = new SessionCell(this.mContext, MrySessionsActivity.this.currentType);
                view3.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                view = view3;
            } else {
                view = LayoutInflater.from(this.mContext).inflate(R.layout.item_session_layout, (ViewGroup) null, false);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder viewHolder, final int i) {
            int itemViewType = viewHolder.getItemViewType();
            if (itemViewType == 0) {
                TextSettingsCell textSettingsCell = (TextSettingsCell) viewHolder.itemView;
                if (i == MrySessionsActivity.this.terminateAllSessionsRow) {
                    textSettingsCell.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText2));
                    if (MrySessionsActivity.this.currentType == 0) {
                        textSettingsCell.setText(LocaleController.getString("TerminateAllSessions", R.string.TerminateAllSessions), false);
                    } else {
                        textSettingsCell.setText(LocaleController.getString("TerminateAllWebSessions", R.string.TerminateAllWebSessions), false);
                    }
                }
                textSettingsCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                return;
            }
            if (itemViewType == 1) {
                TextInfoPrivacyCell textInfoPrivacyCell = (TextInfoPrivacyCell) viewHolder.itemView;
                if (i == MrySessionsActivity.this.terminateAllSessionsDetailRow) {
                    if (MrySessionsActivity.this.currentType == 0) {
                        textInfoPrivacyCell.setText(LocaleController.getString("ClearOtherSessionsHelp", R.string.ClearOtherSessionsHelp));
                        return;
                    } else {
                        textInfoPrivacyCell.setText(LocaleController.getString("ClearOtherWebSessionsHelp", R.string.ClearOtherWebSessionsHelp));
                        return;
                    }
                }
                if (i == MrySessionsActivity.this.otherSessionsTerminateDetail) {
                    if (MrySessionsActivity.this.currentType == 0) {
                        textInfoPrivacyCell.setText(LocaleController.getString("TerminateSessionInfo", R.string.TerminateSessionInfo));
                        return;
                    } else {
                        textInfoPrivacyCell.setText(LocaleController.getString("TerminateWebSessionInfo", R.string.TerminateWebSessionInfo));
                        return;
                    }
                }
                if (i == MrySessionsActivity.this.passwordSessionsDetailRow) {
                    textInfoPrivacyCell.setText(LocaleController.getString("LoginAttemptsInfo", R.string.LoginAttemptsInfo));
                    int unused = MrySessionsActivity.this.otherSessionsTerminateDetail;
                    return;
                }
                return;
            }
            if (itemViewType == 2) {
                TextInfoPrivacyCell textInfoPrivacyCell2 = (TextInfoPrivacyCell) viewHolder.itemView;
                if (i != MrySessionsActivity.this.currentSessionSectionRow) {
                    if (i == MrySessionsActivity.this.otherSessionsSectionRow) {
                        if (MrySessionsActivity.this.currentType == 0) {
                            textInfoPrivacyCell2.setText(LocaleController.getString("OtherSessions", R.string.OtherSessions));
                            return;
                        } else {
                            textInfoPrivacyCell2.setText(LocaleController.getString("OtherWebSessions", R.string.OtherWebSessions));
                            return;
                        }
                    }
                    if (i == MrySessionsActivity.this.passwordSessionsSectionRow) {
                        textInfoPrivacyCell2.setText(LocaleController.getString("LoginAttempts", R.string.LoginAttempts));
                        return;
                    }
                    return;
                }
                textInfoPrivacyCell2.setText(LocaleController.getString("CurrentSession", R.string.CurrentSession));
                return;
            }
            if (itemViewType == 3) {
                ViewGroup.LayoutParams layoutParams = MrySessionsActivity.this.emptyLayout.getLayoutParams();
                if (layoutParams != null) {
                    layoutParams.height = Math.max(AndroidUtilities.dp(220.0f), ((AndroidUtilities.displaySize.y - ActionBar.getCurrentActionBarHeight()) - AndroidUtilities.dp(128.0f)) - (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0));
                    MrySessionsActivity.this.emptyLayout.setLayoutParams(layoutParams);
                    return;
                }
                return;
            }
            if (itemViewType == 5) {
                SessionCell sessionCell = (SessionCell) viewHolder.itemView;
                if (i == MrySessionsActivity.this.currentSessionRow) {
                    sessionCell.setSession(MrySessionsActivity.this.currentSession, (MrySessionsActivity.this.sessions.isEmpty() && MrySessionsActivity.this.passwordSessions.isEmpty()) ? false : true);
                    sessionCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                }
                if (i < MrySessionsActivity.this.otherSessionsStartRow || i >= MrySessionsActivity.this.otherSessionsEndRow) {
                    if (i >= MrySessionsActivity.this.passwordSessionsStartRow && i < MrySessionsActivity.this.passwordSessionsEndRow) {
                        sessionCell.setSession((TLObject) MrySessionsActivity.this.passwordSessions.get(i - MrySessionsActivity.this.passwordSessionsStartRow), i != MrySessionsActivity.this.passwordSessionsEndRow - 1);
                        if (i != MrySessionsActivity.this.passwordSessionsStartRow) {
                            if (i == MrySessionsActivity.this.passwordSessionsStartRow - 1) {
                                sessionCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                                return;
                            } else {
                                sessionCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                                return;
                            }
                        }
                        sessionCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                        return;
                    }
                    return;
                }
                sessionCell.setSession((TLObject) MrySessionsActivity.this.sessions.get(i - MrySessionsActivity.this.otherSessionsStartRow), i != MrySessionsActivity.this.otherSessionsEndRow - 1);
                if (i != MrySessionsActivity.this.otherSessionsStartRow) {
                    if (i == MrySessionsActivity.this.otherSessionsEndRow - 1) {
                        sessionCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                        return;
                    } else {
                        sessionCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                        return;
                    }
                }
                sessionCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                return;
            }
            SessionCell sessionCell2 = (SessionCell) viewHolder.itemView.findViewById(R.attr.sessionCell);
            TextView textView = (TextView) viewHolder.itemView.findViewById(R.attr.btnDelete);
            textView.setBackground(Theme.getSelectorDrawable(false));
            textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$ListAdapter$9hMrpx3HdUXUfu8aztZD9cs6dxw
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$onBindViewHolder$6$MrySessionsActivity$ListAdapter(i, view);
                }
            });
            if (i == MrySessionsActivity.this.currentSessionRow) {
                sessionCell2.setSession(MrySessionsActivity.this.currentSession, (MrySessionsActivity.this.sessions.isEmpty() && MrySessionsActivity.this.passwordSessions.isEmpty()) ? false : true);
                sessionCell2.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                return;
            }
            if (i < MrySessionsActivity.this.otherSessionsStartRow || i >= MrySessionsActivity.this.otherSessionsEndRow) {
                if (i >= MrySessionsActivity.this.passwordSessionsStartRow && i < MrySessionsActivity.this.passwordSessionsEndRow) {
                    sessionCell2.setSession((TLObject) MrySessionsActivity.this.passwordSessions.get(i - MrySessionsActivity.this.passwordSessionsStartRow), i != MrySessionsActivity.this.passwordSessionsEndRow - 1);
                    if (i != MrySessionsActivity.this.passwordSessionsStartRow) {
                        if (i == MrySessionsActivity.this.passwordSessionsEndRow - 1) {
                            sessionCell2.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                            return;
                        } else {
                            sessionCell2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                            return;
                        }
                    }
                    sessionCell2.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                }
                return;
            }
            sessionCell2.setSession((TLObject) MrySessionsActivity.this.sessions.get(i - MrySessionsActivity.this.otherSessionsStartRow), i != MrySessionsActivity.this.otherSessionsEndRow - 1);
            if (i != MrySessionsActivity.this.otherSessionsStartRow) {
                if (i == MrySessionsActivity.this.otherSessionsEndRow - 1) {
                    sessionCell2.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                } else {
                    sessionCell2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    return;
                }
            }
            sessionCell2.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
        }

        public /* synthetic */ void lambda$onBindViewHolder$6$MrySessionsActivity$ListAdapter(final int position, View v) {
            String name;
            if (MrySessionsActivity.this.getParentActivity() == null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(MrySessionsActivity.this.getParentActivity());
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            final boolean[] param = new boolean[1];
            if (MrySessionsActivity.this.currentType != 0) {
                TLRPC.TL_webAuthorization authorization = (TLRPC.TL_webAuthorization) MrySessionsActivity.this.sessions.get(position - MrySessionsActivity.this.otherSessionsStartRow);
                builder.setMessage(LocaleController.formatString("TerminateWebSessionQuestion", R.string.TerminateWebSessionQuestion, authorization.domain));
                FrameLayout frameLayout1 = new FrameLayout(MrySessionsActivity.this.getParentActivity());
                TLRPC.User user = MessagesController.getInstance(MrySessionsActivity.this.currentAccount).getUser(Integer.valueOf(authorization.bot_id));
                if (user != null) {
                    name = UserObject.getFirstName(user);
                } else {
                    name = "";
                }
                CheckBoxCell cell = new CheckBoxCell(MrySessionsActivity.this.getParentActivity(), 1);
                cell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
                cell.setText(LocaleController.formatString("TerminateWebSessionStop", R.string.TerminateWebSessionStop, name), "", false, false);
                cell.setPadding(LocaleController.isRTL ? AndroidUtilities.dp(16.0f) : AndroidUtilities.dp(8.0f), 0, LocaleController.isRTL ? AndroidUtilities.dp(8.0f) : AndroidUtilities.dp(16.0f), 0);
                frameLayout1.addView(cell, LayoutHelper.createFrame(-1.0f, 48.0f, 51, 0.0f, 0.0f, 0.0f, 0.0f));
                cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$ListAdapter$IHKPGqdxUj6s8Na06h2GOD0VNR8
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        MrySessionsActivity.ListAdapter.lambda$null$0(param, view);
                    }
                });
                builder.setCustomViewOffset(16);
                builder.setView(frameLayout1);
            } else {
                builder.setMessage(LocaleController.getString("TerminateSessionQuestion", R.string.TerminateSessionQuestion));
            }
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$ListAdapter$LeCKab6Z_sHvEDP1ZAHDadIkpmM
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$5$MrySessionsActivity$ListAdapter(position, param, dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            MrySessionsActivity.this.showDialog(builder.create());
        }

        static /* synthetic */ void lambda$null$0(boolean[] param, View view) {
            if (!view.isEnabled()) {
                return;
            }
            CheckBoxCell cell1 = (CheckBoxCell) view;
            param[0] = !param[0];
            cell1.setChecked(param[0], true);
        }

        public /* synthetic */ void lambda$null$5$MrySessionsActivity$ListAdapter(int position, boolean[] param, DialogInterface dialogInterface, int option) {
            if (MrySessionsActivity.this.getParentActivity() == null) {
                return;
            }
            final AlertDialog progressDialog = new AlertDialog(MrySessionsActivity.this.getParentActivity(), 3);
            progressDialog.setCanCancel(false);
            progressDialog.show();
            if (MrySessionsActivity.this.currentType == 0) {
                final TLRPC.TL_authorization authorization = (position < MrySessionsActivity.this.otherSessionsStartRow || position >= MrySessionsActivity.this.otherSessionsEndRow) ? (TLRPC.TL_authorization) MrySessionsActivity.this.passwordSessions.get(position - MrySessionsActivity.this.passwordSessionsStartRow) : (TLRPC.TL_authorization) MrySessionsActivity.this.sessions.get(position - MrySessionsActivity.this.otherSessionsStartRow);
                TLRPC.TL_account_resetAuthorization req = new TLRPC.TL_account_resetAuthorization();
                req.hash = authorization.hash;
                ConnectionsManager.getInstance(MrySessionsActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$ListAdapter$ZZC1GUQzBs4-lMdZXyEK9Q7Nf6w
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$null$2$MrySessionsActivity$ListAdapter(progressDialog, authorization, tLObject, tL_error);
                    }
                });
                return;
            }
            final TLRPC.TL_webAuthorization authorization2 = (TLRPC.TL_webAuthorization) MrySessionsActivity.this.sessions.get(position - MrySessionsActivity.this.otherSessionsStartRow);
            TLRPC.TL_account_resetWebAuthorization req2 = new TLRPC.TL_account_resetWebAuthorization();
            req2.hash = authorization2.hash;
            ConnectionsManager.getInstance(MrySessionsActivity.this.currentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$ListAdapter$QelId6-uoSVRMOakxuPUw3zEwc8
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$4$MrySessionsActivity$ListAdapter(progressDialog, authorization2, tLObject, tL_error);
                }
            });
            if (param[0]) {
                MessagesController.getInstance(MrySessionsActivity.this.currentAccount).blockUser(authorization2.bot_id);
            }
        }

        public /* synthetic */ void lambda$null$2$MrySessionsActivity$ListAdapter(final AlertDialog progressDialog, final TLRPC.TL_authorization authorization, TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$ListAdapter$F_xeeeHjYvHTxXkhdl0LmqI47SU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$1$MrySessionsActivity$ListAdapter(progressDialog, error, authorization);
                }
            });
        }

        public /* synthetic */ void lambda$null$1$MrySessionsActivity$ListAdapter(AlertDialog progressDialog, TLRPC.TL_error error, TLRPC.TL_authorization authorization) {
            try {
                progressDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
            if (error == null) {
                MrySessionsActivity.this.sessions.remove(authorization);
                MrySessionsActivity.this.passwordSessions.remove(authorization);
                MrySessionsActivity.this.updateRows();
                if (MrySessionsActivity.this.listAdapter != null) {
                    MrySessionsActivity.this.listAdapter.notifyDataSetChanged();
                }
            }
        }

        public /* synthetic */ void lambda$null$4$MrySessionsActivity$ListAdapter(final AlertDialog progressDialog, final TLRPC.TL_webAuthorization authorization, TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MrySessionsActivity$ListAdapter$cZw8wa-PrYD1kG5DyQpp2GWtzBI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$3$MrySessionsActivity$ListAdapter(progressDialog, error, authorization);
                }
            });
        }

        public /* synthetic */ void lambda$null$3$MrySessionsActivity$ListAdapter(AlertDialog progressDialog, TLRPC.TL_error error, TLRPC.TL_webAuthorization authorization) {
            try {
                progressDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
            if (error == null) {
                MrySessionsActivity.this.sessions.remove(authorization);
                MrySessionsActivity.this.updateRows();
                if (MrySessionsActivity.this.listAdapter != null) {
                    MrySessionsActivity.this.listAdapter.notifyDataSetChanged();
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == MrySessionsActivity.this.terminateAllSessionsRow) {
                return 0;
            }
            if (position != MrySessionsActivity.this.terminateAllSessionsDetailRow && position != MrySessionsActivity.this.otherSessionsTerminateDetail && position != MrySessionsActivity.this.passwordSessionsDetailRow) {
                if (position != MrySessionsActivity.this.currentSessionSectionRow && position != MrySessionsActivity.this.otherSessionsSectionRow && position != MrySessionsActivity.this.passwordSessionsSectionRow) {
                    if (position != MrySessionsActivity.this.noOtherSessionsRow) {
                        if (position < MrySessionsActivity.this.otherSessionsStartRow || position >= MrySessionsActivity.this.otherSessionsEndRow) {
                            if (position < MrySessionsActivity.this.passwordSessionsStartRow || position >= MrySessionsActivity.this.passwordSessionsEndRow) {
                                return position == MrySessionsActivity.this.currentSessionRow ? 5 : 0;
                            }
                            return 4;
                        }
                        return 4;
                    }
                    return 3;
                }
                return 2;
            }
            return 1;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{TextSettingsCell.class, HeaderCell.class, SessionCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.imageView, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_sessions_devicesImage), new ThemeDescription(this.textView1, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.textView2, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.emptyView, ThemeDescription.FLAG_PROGRESSBAR, null, null, null, null, Theme.key_progressCircle), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteRedText2), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, 0, new Class[]{SessionCell.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{SessionCell.class}, new String[]{"onlineTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{SessionCell.class}, new String[]{"onlineTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText3), new ThemeDescription(this.listView, 0, new Class[]{SessionCell.class}, new String[]{"detailTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{SessionCell.class}, new String[]{"detailExTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText3)};
    }
}
