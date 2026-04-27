package im.uwrkaxlmjj.ui.hui.contacts;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.text.Editable;
import android.text.InputFilter;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import butterknife.BindView;
import butterknife.OnClick;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.WalletDialog;
import im.uwrkaxlmjj.ui.hcells.MryDividerCell;
import im.uwrkaxlmjj.ui.hui.CharacterParser;
import im.uwrkaxlmjj.ui.hui.contacts.AddGroupingUserActivity;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.sidebar.SideBar;
import im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class CreateGroupingActivity extends BaseFragment {
    private static final int item_done = 1;
    private boolean hasEmoji;
    private ListAdapter mAdapter;

    @BindView(R.attr.et_group_name)
    MryEditText mEtGroupName;

    @BindView(R.attr.fl_group_name)
    FrameLayout mFlGroupName;

    @BindView(R.attr.iv_clear)
    ImageView mIvClear;

    @BindView(R.attr.ll_container)
    LinearLayout mLlContainer;

    @BindView(R.attr.ll_not_support_emoji_tips)
    LinearLayout mLlNotSupportEmojiTips;

    @BindView(R.attr.rv_users)
    RecyclerListView mRvUsers;

    @BindView(R.attr.sideBar)
    SideBar mSideBar;

    @BindView(R.attr.tv_add_user)
    TextView mTvAddUser;

    @BindView(R.attr.tv_char)
    MryTextView mTvChar;
    private TextWatcher mWatcher;
    private MryTextView tvOkView;
    private List<TLRPC.User> selectedUsers = new ArrayList();
    private HashMap<String, ArrayList<TLRPC.User>> map = new HashMap<>();
    private ArrayList<String> mapKeysList = new ArrayList<>();
    private boolean isFirst = true;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        this.swipeBackEnabled = false;
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_create_grouping_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        useButterKnife();
        initActionbar();
        initView();
        return this.fragmentView;
    }

    private void initActionbar() {
        this.actionBar.setAddToContainer(false);
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString("AddGrouping", R.string.AddGrouping));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.contacts.CreateGroupingActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    if (!TextUtils.isEmpty(CreateGroupingActivity.this.mEtGroupName.getText())) {
                        CreateGroupingActivity.this.showSaveDialog();
                        return;
                    } else {
                        CreateGroupingActivity.this.finishFragment();
                        return;
                    }
                }
                if (id == 1) {
                    CreateGroupingActivity.this.createGrouping();
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        MryTextView mryTextView = new MryTextView(getParentActivity());
        this.tvOkView = mryTextView;
        mryTextView.setEnabled(false);
        this.tvOkView.setText(LocaleController.getString("Done", R.string.Done));
        this.tvOkView.setTextSize(1, 14.0f);
        this.tvOkView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.tvOkView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultTitle));
        this.tvOkView.setGravity(16);
        menu.addItemView(1, this.tvOkView);
        ((RelativeLayout) this.fragmentView).addView(this.actionBar, 0);
    }

    private void initView() {
        RelativeLayout.LayoutParams lp1 = (RelativeLayout.LayoutParams) this.mLlContainer.getLayoutParams();
        lp1.topMargin = ActionBar.getCurrentActionBarHeight() + AndroidUtilities.statusBarHeight;
        this.mLlContainer.setLayoutParams(lp1);
        RelativeLayout.LayoutParams lp2 = (RelativeLayout.LayoutParams) this.mLlNotSupportEmojiTips.getLayoutParams();
        lp2.topMargin = AndroidUtilities.statusBarHeight;
        this.mLlNotSupportEmojiTips.setLayoutParams(lp2);
        this.mFlGroupName.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.mTvAddUser.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.mTvAddUser.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
        Drawable[] ds = this.mTvAddUser.getCompoundDrawables();
        if (ds[0] != null) {
            ds[0].setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton), PorterDuff.Mode.SRC_IN));
            this.mTvAddUser.setCompoundDrawables(ds[0], ds[1], ds[2], ds[3]);
        }
        this.mLlNotSupportEmojiTips.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.mEtGroupName.setFilters(new InputFilter[]{new LengthFilter(28)});
        MryEditText mryEditText = this.mEtGroupName;
        TextWatcher textWatcher = new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.contacts.CreateGroupingActivity.2
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                CreateGroupingActivity.this.hasEmoji = false;
                for (int i = 0; i < s.length(); i++) {
                    int type = Character.getType(s.charAt(i));
                    if (type == 19 || type == 28) {
                        CreateGroupingActivity.this.hasEmoji = true;
                        break;
                    }
                }
                CreateGroupingActivity.this.mLlNotSupportEmojiTips.setVisibility(CreateGroupingActivity.this.hasEmoji ? 0 : 8);
                CreateGroupingActivity.this.actionBar.setVisibility(CreateGroupingActivity.this.hasEmoji ? 4 : 0);
                CreateGroupingActivity.this.mIvClear.setVisibility(TextUtils.isEmpty(s) ? 4 : 0);
                CreateGroupingActivity.this.tvOkView.setEnabled(!TextUtils.isEmpty(s));
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                if (TextUtils.isEmpty(CreateGroupingActivity.this.mEtGroupName.getHint())) {
                    CreateGroupingActivity.this.mEtGroupName.setHint(LocaleController.getString(R.string.EmptyGroupingNameTips));
                }
            }
        };
        this.mWatcher = textWatcher;
        mryEditText.addTextChangedListener(textWatcher);
        this.mEtGroupName.setOnFocusChangeListener(new View.OnFocusChangeListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$CreateGroupingActivity$hLoCGsX5A5f1NG9PczVKOqyTHA4
            @Override // android.view.View.OnFocusChangeListener
            public final void onFocusChange(View view, boolean z) {
                this.f$0.lambda$initView$0$CreateGroupingActivity(view, z);
            }
        });
        initSideBar();
        initList();
    }

    public /* synthetic */ void lambda$initView$0$CreateGroupingActivity(View v, boolean hasFocus) {
        if (v.getId() == R.attr.et_group_name && this.isFirst && hasFocus) {
            this.mEtGroupName.setHint("");
            this.isFirst = false;
        }
    }

    private void initSideBar() {
        this.mSideBar.setTextView(this.mTvChar);
        this.mSideBar.setOnTouchingLetterChangedListener(new SideBar.OnTouchingLetterChangedListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$CreateGroupingActivity$_llYylG785xfMQmDiA_vFaHOgYc
            @Override // im.uwrkaxlmjj.ui.hviews.sidebar.SideBar.OnTouchingLetterChangedListener
            public final void onTouchingLetterChanged(String str) {
                this.f$0.lambda$initSideBar$1$CreateGroupingActivity(str);
            }
        });
    }

    public /* synthetic */ void lambda$initSideBar$1$CreateGroupingActivity(String s) {
        if ("↑".equals(s)) {
            this.mRvUsers.scrollToPosition(0);
            return;
        }
        if (!"☆".equals(s)) {
            int section = this.mAdapter.getSectionForChar(s.charAt(0));
            int position = this.mAdapter.getPositionForSection(section);
            if (position != -1) {
                this.mRvUsers.getLayoutManager().scrollToPosition(position);
            }
        }
    }

    private void initList() {
        this.mRvUsers.setLayoutManager(new LinearLayoutManager(getParentActivity()));
        ListAdapter listAdapter = new ListAdapter();
        this.mAdapter = listAdapter;
        listAdapter.setList(this.mapKeysList, this.map);
        this.mRvUsers.setAdapter(this.mAdapter);
        this.mRvUsers.addOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.CreateGroupingActivity.3
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
                LinearLayoutManager layoutManager = (LinearLayoutManager) recyclerView.getLayoutManager();
                int firstPosition = layoutManager.findFirstVisibleItemPosition();
                String s = CreateGroupingActivity.this.mAdapter.getLetter(firstPosition);
                CreateGroupingActivity.this.mSideBar.setChooseChar(s);
            }
        });
        this.mAdapter.notifyDataSetChanged();
    }

    @OnClick({R.attr.iv_clear, R.attr.tv_add_user})
    public void onViewClicked(View view) {
        int id = view.getId();
        if (id == R.attr.iv_clear) {
            this.mEtGroupName.setText((CharSequence) null);
        } else if (id == R.attr.tv_add_user) {
            AddGroupingUserActivity fragment = new AddGroupingUserActivity(this.selectedUsers, 1);
            fragment.setDelegate(new AddGroupingUserActivity.AddGroupingUserActivityDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$CreateGroupingActivity$ZlhVXWXw_VxQs6YaUpM-ZFmdiDo
                @Override // im.uwrkaxlmjj.ui.hui.contacts.AddGroupingUserActivity.AddGroupingUserActivityDelegate
                public final void didSelectedContact(ArrayList arrayList) {
                    this.f$0.lambda$onViewClicked$2$CreateGroupingActivity(arrayList);
                }
            });
            presentFragment(fragment);
        }
    }

    public /* synthetic */ void lambda$onViewClicked$2$CreateGroupingActivity(ArrayList users) {
        this.selectedUsers.clear();
        this.selectedUsers.addAll(users);
        groupingUsers(this.selectedUsers);
        ListAdapter listAdapter = this.mAdapter;
        if (listAdapter != null) {
            listAdapter.setList(this.mapKeysList, this.map);
            this.mAdapter.notifyDataSetChanged();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SectionsAdapter {
        private ArrayList<String> list;
        private HashMap<String, ArrayList<TLRPC.User>> updateMaps;

        private ListAdapter() {
        }

        public void setList(ArrayList<String> list, HashMap<String, ArrayList<TLRPC.User>> map) {
            this.list = list;
            this.updateMaps = map;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getSectionCount() {
            return this.list.size();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getCountForSection(int section) {
            return this.updateMaps.get(this.list.get(section)).size();
        }

        public int getSectionForChar(char section) {
            for (int i = 0; i < getSectionCount(); i++) {
                String sortStr = this.list.get(i);
                char firstChar = sortStr.toUpperCase().charAt(0);
                if (firstChar == section) {
                    return i;
                }
            }
            return -1;
        }

        public int getPositionForSection(int section) {
            if (section == -1) {
                return -1;
            }
            int positionStart = 0;
            for (int i = 0; i < getSectionCount(); i++) {
                if (i >= section) {
                    return positionStart;
                }
                int count = getCountForSection(i);
                positionStart += count;
            }
            return -1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public String getLetter(int position) {
            int section = getSectionForPosition(position);
            if (section != -1) {
                return this.list.get(section);
            }
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public int getPositionForScrollProgress(float progress) {
            return 0;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public boolean isEnabled(int section, int row) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            SwipeLayout swipeLayout = new SwipeLayout(CreateGroupingActivity.this.getParentActivity()) { // from class: im.uwrkaxlmjj.ui.hui.contacts.CreateGroupingActivity.ListAdapter.1
                @Override // android.view.View
                public boolean onTouchEvent(MotionEvent event) {
                    if (isExpanded()) {
                        return true;
                    }
                    return super.onTouchEvent(event);
                }
            };
            View view = LayoutInflater.from(CreateGroupingActivity.this.getParentActivity()).inflate(R.layout.item_create_grouping, parent, false);
            swipeLayout.setUpView(view);
            return new RecyclerListView.Holder(swipeLayout);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public void onBindViewHolder(int section, int position, RecyclerView.ViewHolder holder) {
            SwipeLayout swipeLayout = (SwipeLayout) holder.itemView;
            swipeLayout.setItemWidth(AndroidUtilities.dp(65.0f));
            View content = swipeLayout.getMainLayout();
            BackupImageView ivAvatar = (BackupImageView) content.findViewById(R.attr.iv_avatar);
            MryTextView tvName = (MryTextView) content.findViewById(R.attr.tv_name);
            MryDividerCell divider = (MryDividerCell) content.findViewById(R.attr.divider);
            final TLRPC.User user = (TLRPC.User) getItem(section, position);
            ivAvatar.setRoundRadius(AndroidUtilities.dp(7.5f));
            AvatarDrawable drawable = new AvatarDrawable(user);
            drawable.setColor(Theme.getColor(Theme.key_avatar_backgroundInProfileBlue));
            ivAvatar.setImage(ImageLocation.getForUser(user, false), "50_50", drawable, user);
            tvName.setText(UserObject.getName(user));
            if (getItemCount() != 1) {
                if (section != 0 || position != 0) {
                    if (section == getSectionCount() - 1 && position == getCountForSection(section) - 1) {
                        divider.setVisibility(8);
                        content.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    } else {
                        content.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    }
                } else {
                    content.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                }
            } else {
                content.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                divider.setVisibility(8);
            }
            int[] rightColors = {-570319};
            String[] rightTexts = {LocaleController.getString(R.string.Delete)};
            int[] rightTextColors = {-1};
            swipeLayout.setRightTexts(rightTexts);
            swipeLayout.setRightTextColors(rightTextColors);
            swipeLayout.setRightColors(rightColors);
            swipeLayout.setTextSize(AndroidUtilities.sp2px(14.0f));
            swipeLayout.rebuildLayout();
            swipeLayout.setOnSwipeItemClickListener(new SwipeLayout.OnSwipeItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$CreateGroupingActivity$ListAdapter$vvYZVy2VQ2NKQT4TWKk9aIAYaZk
                @Override // im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout.OnSwipeItemClickListener
                public final void onSwipeItemClick(boolean z, int i) {
                    this.f$0.lambda$onBindViewHolder$0$CreateGroupingActivity$ListAdapter(user, z, i);
                }
            });
        }

        public /* synthetic */ void lambda$onBindViewHolder$0$CreateGroupingActivity$ListAdapter(TLRPC.User user, boolean left, int index) {
            if (!left && index == 0) {
                CreateGroupingActivity.this.selectedUsers.remove(user);
                CreateGroupingActivity createGroupingActivity = CreateGroupingActivity.this;
                createGroupingActivity.groupingUsers(createGroupingActivity.selectedUsers);
                setList(CreateGroupingActivity.this.mapKeysList, CreateGroupingActivity.this.map);
                notifyDataSetChanged();
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getItemViewType(int section, int position) {
            return 0;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public Object getItem(int section, int position) {
            String key = this.list.get(section);
            ArrayList<TLRPC.User> updates = this.updateMaps.get(key);
            return updates.get(position);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public View getSectionHeaderView(int section, View view) {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int count = 0;
            if (this.updateMaps != null) {
                for (String item : this.list) {
                    count += this.updateMaps.get(item).size();
                }
            }
            return count;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            super.notifyDataSetChanged();
            if (getItemCount() == 0) {
                CreateGroupingActivity.this.mSideBar.setVisibility(8);
            } else {
                CreateGroupingActivity.this.mSideBar.setVisibility(0);
                CreateGroupingActivity.this.mSideBar.setChars((String[]) CreateGroupingActivity.this.mapKeysList.toArray(new String[CreateGroupingActivity.this.mapKeysList.size()]));
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showSaveDialog() {
        WalletDialog dialog = new WalletDialog(getParentActivity());
        dialog.setMessage(LocaleController.getString("SaveGroupingChangeTips", R.string.SaveGroupingChangeTips));
        dialog.setPositiveButton(LocaleController.getString("Save", R.string.Save), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$CreateGroupingActivity$OwEspbyWrLwp3iJnNhXlMT-EXTw
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showSaveDialog$3$CreateGroupingActivity(dialogInterface, i);
            }
        });
        dialog.setNegativeButton(LocaleController.getString("NotSave", R.string.NotSave), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$CreateGroupingActivity$B-7Vgd4nwskYxf4SnmJlsIqsg44
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showSaveDialog$4$CreateGroupingActivity(dialogInterface, i);
            }
        });
        showDialog(dialog);
    }

    public /* synthetic */ void lambda$showSaveDialog$3$CreateGroupingActivity(DialogInterface dialogInterface, int i) {
        createGrouping();
    }

    public /* synthetic */ void lambda$showSaveDialog$4$CreateGroupingActivity(DialogInterface dialogInterface, int i) {
        finishFragment();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void createGrouping() {
        final AlertDialog alertDialog = new AlertDialog(getParentActivity(), 3);
        TLRPCContacts.TL_createGroup req = new TLRPCContacts.TL_createGroup();
        req.title = this.mEtGroupName.getText().toString();
        req.random_id = getConnectionsManager().getCurrentTime();
        for (TLRPC.User user : this.selectedUsers) {
            TLRPC.InputUser inputUser = getMessagesController().getInputUser(user);
            if (inputUser != null) {
                req.users.add(inputUser);
            }
        }
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$CreateGroupingActivity$Q4DaqE9yjN9PIALrdOXK2en7aFk
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$createGrouping$6$CreateGroupingActivity(alertDialog, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId, this.classGuid);
        alertDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$CreateGroupingActivity$56pVIoxSDs4WtTvcH4pMhOEWRK8
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$createGrouping$7$CreateGroupingActivity(reqId, dialogInterface);
            }
        });
        showDialog(alertDialog);
    }

    public /* synthetic */ void lambda$createGrouping$6$CreateGroupingActivity(final AlertDialog alertDialog, TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$CreateGroupingActivity$fwlrXW7VzwNd5ZykFwjgc_NH11c
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$CreateGroupingActivity(alertDialog, error);
            }
        });
    }

    public /* synthetic */ void lambda$null$5$CreateGroupingActivity(AlertDialog alertDialog, TLRPC.TL_error error) {
        alertDialog.dismiss();
        if (error == null) {
            finishFragment();
        } else {
            ToastUtils.show((CharSequence) error.text);
        }
    }

    public /* synthetic */ void lambda$createGrouping$7$CreateGroupingActivity(int reqId, DialogInterface dialog1) {
        getConnectionsManager().cancelRequest(reqId, true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        TextWatcher textWatcher;
        super.onFragmentDestroy();
        MryEditText mryEditText = this.mEtGroupName;
        if (mryEditText != null && (textWatcher = this.mWatcher) != null) {
            mryEditText.removeTextChangedListener(textWatcher);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void groupingUsers(List<TLRPC.User> users) {
        String key;
        if (users == null) {
            return;
        }
        this.mapKeysList.clear();
        this.map.clear();
        for (TLRPC.User user : users) {
            String key2 = CharacterParser.getInstance().getSelling(UserObject.getFirstName(user));
            if (key2.length() > 1) {
                key2 = key2.substring(0, 1);
            }
            if (key2.length() == 0) {
                key = "#";
            } else {
                key = key2.toUpperCase();
            }
            ArrayList<TLRPC.User> arr = this.map.get(key);
            if (arr == null) {
                arr = new ArrayList<>();
                this.map.put(key, arr);
                this.mapKeysList.add(key);
            }
            arr.add(user);
        }
        Collections.sort(this.mapKeysList, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$CreateGroupingActivity$voXw-xep-5WLEQmdxoc6lcWcLak
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return CreateGroupingActivity.lambda$groupingUsers$8((String) obj, (String) obj2);
            }
        });
    }

    static /* synthetic */ int lambda$groupingUsers$8(String s1, String s2) {
        char cv1 = s1.charAt(0);
        char cv2 = s2.charAt(0);
        if (cv1 == '#') {
            return 1;
        }
        if (cv2 == '#') {
            return -1;
        }
        return s1.compareTo(s2);
    }

    private class LengthFilter implements InputFilter {
        private int maxLen;

        public LengthFilter(int maxLen) {
            this.maxLen = maxLen;
        }

        @Override // android.text.InputFilter
        public CharSequence filter(CharSequence source, int start, int end, Spanned dest, int dstart, int dend) {
            int dindex = 0;
            int count = 0;
            while (count <= this.maxLen && dindex < dest.length()) {
                int dindex2 = dindex + 1;
                char c = dest.charAt(dindex);
                if (c < 128) {
                    count++;
                } else {
                    count += 2;
                }
                dindex = dindex2;
            }
            int dindex3 = this.maxLen;
            if (count > dindex3) {
                return dest.subSequence(0, dindex - 1);
            }
            int sindex = 0;
            while (count <= this.maxLen && sindex < source.length()) {
                int sindex2 = sindex + 1;
                char c2 = source.charAt(sindex);
                if (c2 < 128) {
                    count++;
                } else {
                    count += 2;
                }
                sindex = sindex2;
            }
            if (count > this.maxLen) {
                sindex--;
            }
            return source.subSequence(0, sindex);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        if (!this.hasEmoji && !TextUtils.isEmpty(this.mEtGroupName.getText())) {
            showSaveDialog();
            return false;
        }
        return super.onBackPressed();
    }
}
