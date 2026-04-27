package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.DividerItemDecoration;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.AddAccountActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class AddAccountActivity extends BaseFragment {
    private ListAdapter listAdapter;
    private RecyclerListView listView;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_add_account, (ViewGroup) null);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initActionBar();
        initList();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString(R.string.AddAccount2));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.AddAccountActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    AddAccountActivity.this.finishFragment();
                }
            }
        });
    }

    private void initList() {
        MryTextView tvTips = (MryTextView) this.fragmentView.findViewById(R.attr.tv_action_tips);
        tvTips.setText(LocaleController.getString("ActionTips", R.string.TouchTips));
        RecyclerListView recyclerListView = (RecyclerListView) this.fragmentView.findViewById(R.attr.listView);
        this.listView = recyclerListView;
        recyclerListView.setLayoutManager(new LinearLayoutManager(getParentActivity()));
        DividerItemDecoration divider = new DividerItemDecoration(getParentActivity(), 1);
        divider.setDrawable(getParentActivity().getResources().getDrawable(R.drawable.shape_transaction_list_divider));
        this.listView.addItemDecoration(divider);
        RecyclerListView recyclerListView2 = this.listView;
        ListAdapter listAdapter = new ListAdapter();
        this.listAdapter = listAdapter;
        recyclerListView2.setAdapter(listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$AddAccountActivity$WNAvb1F_GNzeuBwJABKGhhD2EBc
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$0$AddAccountActivity(view, i);
            }
        });
    }

    public /* synthetic */ void lambda$initList$0$AddAccountActivity(View view, int position) {
        if (position == this.listAdapter.getItemCount() - 1) {
            if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                int freeAccount = -1;
                int a = 0;
                while (true) {
                    if (a >= 3) {
                        break;
                    }
                    if (UserConfig.getInstance(a).isClientActivated()) {
                        a++;
                    } else {
                        freeAccount = a;
                        break;
                    }
                }
                if (freeAccount >= 0) {
                    presentFragment(new LoginContronllerActivity(freeAccount), true);
                    return;
                }
                return;
            }
            ToastUtils.show((CharSequence) LocaleController.getString(R.string.visual_call_stop_add_account));
            return;
        }
        int accountNumber = this.listAdapter.getAccountNumber(position);
        if (accountNumber != -1) {
            ((LaunchActivity) getParentActivity()).switchToAccount(accountNumber, true);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SelectionAdapter {
        private ArrayList<Integer> accountNumbers = new ArrayList<>();

        public ListAdapter() {
            resetItems();
        }

        private void resetItems() {
            this.accountNumbers.clear();
            for (int a = 0; a < 3; a++) {
                if (UserConfig.getInstance(a).isClientActivated()) {
                    this.accountNumbers.add(Integer.valueOf(a));
                }
            }
            Collections.sort(this.accountNumbers, new Comparator() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$AddAccountActivity$ListAdapter$Rl1YK4s4CXEnmJHwSrf7O-D_tCM
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return AddAccountActivity.ListAdapter.lambda$resetItems$0((Integer) obj, (Integer) obj2);
                }
            });
        }

        static /* synthetic */ int lambda$resetItems$0(Integer o1, Integer o2) {
            long l1 = UserConfig.getInstance(o1.intValue()).loginTime;
            long l2 = UserConfig.getInstance(o2.intValue()).loginTime;
            if (l1 > l2) {
                return 1;
            }
            if (l1 < l2) {
                return -1;
            }
            return 0;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = LayoutInflater.from(AddAccountActivity.this.getParentActivity()).inflate(R.layout.item_login_account, parent, false);
            } else if (viewType == 1) {
                view = LayoutInflater.from(AddAccountActivity.this.getParentActivity()).inflate(R.layout.item_add_account, parent, false);
            }
            view.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            if (holder.getItemViewType() == 0) {
                BackupImageView ivAvatar = (BackupImageView) holder.itemView.findViewById(R.attr.iv_avatar);
                MryTextView tvPhone = (MryTextView) holder.itemView.findViewById(R.attr.tv_phone);
                MryTextView tvCurrent = (MryTextView) holder.itemView.findViewById(R.attr.tv_current);
                tvCurrent.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(2.0f), -1181185));
                tvCurrent.setText(LocaleController.getString("Currently used", R.string.CurrentUsed));
                TLRPC.User user = UserConfig.getInstance(this.accountNumbers.get(position).intValue()).getCurrentUser();
                if (user != null) {
                    ivAvatar.setRoundRadius(AndroidUtilities.dp(7.5f));
                    AvatarDrawable drawable = new AvatarDrawable();
                    drawable.setInfo(user);
                    ivAvatar.setImage(ImageLocation.getForUser(user, false), "50_50", drawable, user);
                    tvPhone.setText(UserObject.getName(user));
                    tvCurrent.setVisibility(user.id != AddAccountActivity.this.getUserConfig().getClientUserId() ? 8 : 0);
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return position == getItemCount() - 1 ? 1 : 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int count = 1 + this.accountNumbers.size();
            return count;
        }

        public int getAccountNumber(int position) {
            if (position != getItemCount() - 1) {
                return this.accountNumbers.get(position).intValue();
            }
            return -1;
        }
    }
}
