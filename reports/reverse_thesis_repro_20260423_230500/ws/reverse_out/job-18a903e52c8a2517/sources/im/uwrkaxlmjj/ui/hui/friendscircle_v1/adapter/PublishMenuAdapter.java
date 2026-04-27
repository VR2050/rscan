package im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter;

import android.content.Context;
import android.graphics.PorterDuff;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.bean.RespTopicBean;
import com.bjz.comm.net.bean.TopicBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter;
import im.uwrkaxlmjj.ui.hui.decoration.DefaultItemDecoration;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.PublishMenuAdapter.Menu;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PublishMenuAdapter<M extends Menu> extends PageSelectionAdapter<M, PageHolder> {
    private MenuMentionUserAdapter mentionUserAdapter;
    private RecyclerListView.OnItemClickListener menuUserItemClickListener;
    private RecyclerListView.OnItemClickListener onItemClickListener;

    public PublishMenuAdapter(Context context, int... openMenuRows) {
        super(context);
        setShowLoadMoreViewEnable(false);
        setData(createMenuData(openMenuRows));
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
    public PageHolder onCreateViewHolderForChild(ViewGroup parent, int viewType) {
        return new PageHolder(LayoutInflater.from(getContext()).inflate(R.layout.fc_item_publish_menu, parent, false));
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
    public void onBindViewHolderForChild(PageHolder holder, int position, final M item) {
        holder.itemView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.-$$Lambda$PublishMenuAdapter$6HaxG3jXC-nN-s9RLlOyKl_Qods
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$onBindViewHolderForChild$0$PublishMenuAdapter(item, view);
            }
        });
        holder.setGone(R.attr.bottomDivider, position != getDataCount() - 1);
        holder.setTextColor(R.attr.tvTitleLeft, item.hasValue() ? -13709571 : Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        holder.setTextColor(R.attr.tvTitleRight, Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
        holder.setImageResId(R.attr.ivLeftIcon, item.icon);
        holder.setImageColorFilter(R.attr.ivLeftIcon, item.hasValue() ? -13709571 : Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6), PorterDuff.Mode.SRC_IN);
        RecyclerListView rv = (RecyclerListView) holder.getView(R.attr.mentionUserRv);
        holder.setText(R.attr.tvTitleLeft, (item.type == 1 && item.hasValue()) ? item.getRightValue() : item.leftTitle);
        if (item.type == 0) {
            holder.setGone(R.attr.tvTitleRight, true);
            holder.setGone((View) rv, false);
            if (this.mentionUserAdapter == null) {
                this.mentionUserAdapter = new MenuMentionUserAdapter(getContext());
            }
            rv.setLayoutManager(new LinearLayoutManager(getContext(), 0, true));
            if (rv.getItemDecorationCount() == 0) {
                rv.addItemDecoration(new DefaultItemDecoration().setDividerWidth(AndroidUtilities.dp(5.0f)));
            }
            rv.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.-$$Lambda$PublishMenuAdapter$E7pIxADXHXkfYRJoRx_09noTGvM
                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                public final void onItemClick(View view, int i) {
                    this.f$0.lambda$onBindViewHolderForChild$1$PublishMenuAdapter(item, view, i);
                }
            });
            rv.setAdapter(this.mentionUserAdapter);
            this.mentionUserAdapter.setData(((MenuMentionUser) item).users);
            return;
        }
        holder.setGone((View) rv, true);
        if (item.type == 1) {
            holder.setGone(R.attr.tvTitleRight, true);
        } else {
            holder.setGone(R.attr.tvTitleRight, false);
            holder.getView(R.attr.tvTitleRight).setLayoutParams(LayoutHelper.createLinear(-2, -2, 2.0f, 5, 0, 0, 0));
        }
        holder.setText(R.attr.tvTitleRight, item.hasValue() ? item.getRightValue() : "");
    }

    public /* synthetic */ void lambda$onBindViewHolderForChild$0$PublishMenuAdapter(Menu item, View v) {
        RecyclerListView.OnItemClickListener onItemClickListener = this.onItemClickListener;
        if (onItemClickListener != null) {
            onItemClickListener.onItemClick(v, item.type);
        }
    }

    public /* synthetic */ void lambda$onBindViewHolderForChild$1$PublishMenuAdapter(Menu item, View view, int position1) {
        RecyclerListView.OnItemClickListener onItemClickListener = this.menuUserItemClickListener;
        if (onItemClickListener != null) {
            onItemClickListener.onItemClick(view, item.type);
        }
    }

    public MenuMentionUser getMenuMentionUser() {
        Menu menu = getMenu(0);
        if (menu != null) {
            return (MenuMentionUser) menu;
        }
        return null;
    }

    public MenuLocation getMenuLocation() {
        Menu menu = getMenu(1);
        if (menu != null) {
            return (MenuLocation) menu;
        }
        return null;
    }

    public MenuTopic getMenuTopic() {
        Menu menu = getMenu(2);
        if (menu != null) {
            return (MenuTopic) menu;
        }
        return null;
    }

    public MenuWhoCanWatch getMenuWhoCanWatch() {
        Menu menu = getMenu(3);
        if (menu != null) {
            return (MenuWhoCanWatch) menu;
        }
        return null;
    }

    public void updateMentionUserRow(List<TLRPC.User> users) {
        MenuMentionUser menu = getMenuMentionUser();
        if (menu == null) {
            return;
        }
        menu.users = users;
        notifyDataSetChanged();
    }

    public List<TLRPC.User> getMentionRowUsers() {
        MenuMentionUser menu = getMenuMentionUser();
        return menu != null ? menu.users : new ArrayList();
    }

    public void updateTopicRow(HashMap<String, RespTopicBean.Item> topicMap) {
        MenuTopic menu = getMenuTopic();
        if (menu == null) {
            return;
        }
        menu.topicMap = topicMap;
        notifyDataSetChanged();
    }

    public List<RespTopicBean.Item> getTopicRowRespTopicsList() {
        MenuTopic menu = getMenuTopic();
        return menu == null ? new ArrayList() : menu.getRespTopics();
    }

    public ArrayList<TopicBean> getTopicRowTopicsBeanList() {
        MenuTopic menu = getMenuTopic();
        return menu == null ? new ArrayList<>() : menu.getTopicBeans();
    }

    public void updateWhoCanWatchRow(List<TLRPC.User> users, int privicyType) {
        MenuWhoCanWatch menu = getMenuWhoCanWatch();
        if (menu == null) {
            return;
        }
        menu.users = users;
        menu.privicyType = privicyType;
        notifyDataSetChanged();
    }

    public List<TLRPC.User> getWhoCanWatchRowUsers() {
        MenuWhoCanWatch menu = getMenuWhoCanWatch();
        return menu != null ? menu.users : new ArrayList();
    }

    public int getWhoCanWatchRowPrivicyType() {
        MenuWhoCanWatch menu = getMenuWhoCanWatch();
        if (menu != null) {
            return menu.privicyType;
        }
        return 0;
    }

    public M getMenu(int i) {
        return (M) getItem(i);
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
    public M getItem(int type) {
        for (M m : getData()) {
            if (m.type == type) {
                return m;
            }
        }
        return null;
    }

    public PublishMenuAdapter setOnItemClickListener(RecyclerListView.OnItemClickListener onItemClickListener) {
        this.onItemClickListener = onItemClickListener;
        return this;
    }

    public PublishMenuAdapter setMenuUserItemClickListener(RecyclerListView.OnItemClickListener menuUserItemClickListener) {
        this.menuUserItemClickListener = menuUserItemClickListener;
        return this;
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
    public void destroy() {
        super.destroy();
        MenuMentionUserAdapter menuMentionUserAdapter = this.mentionUserAdapter;
        if (menuMentionUserAdapter != null) {
            menuMentionUserAdapter.destroy();
            this.mentionUserAdapter = null;
        }
        this.menuUserItemClickListener = null;
    }

    public static <M extends Menu> List<M> createMenuData(int... openMenuRows) {
        List<M> list = new ArrayList<>(openMenuRows.length);
        for (int i = 0; i < openMenuRows.length; i++) {
            M menu = null;
            int i2 = openMenuRows[i];
            if (i2 == 0) {
                menu = new MenuMentionUser();
                menu.icon = R.drawable.fc_icon_location_default;
                menu.leftTitle = LocaleController.getString(R.string.WhoToRemindToLook);
            } else if (i2 == 1) {
                menu = new MenuLocation();
                menu.icon = R.drawable.fc_icon_location_default;
                menu.leftTitle = LocaleController.getString(R.string.friendscircle_publish_choose_location);
            } else if (i2 == 2) {
                menu = new MenuTopic();
                menu.icon = R.drawable.fc_icon_topics_default;
                menu.leftTitle = LocaleController.getString(R.string.friendscircle_publish_choose_topics);
            } else if (i2 == 3) {
                menu = new MenuWhoCanWatch();
                menu.icon = R.drawable.fc_icon_location_default;
                menu.leftTitle = LocaleController.getString(R.string.WhoCanWatchIt);
            }
            if (menu != null) {
                menu.type = openMenuRows[i];
                list.add(menu);
            }
        }
        return list;
    }

    public static class MenuMentionUserAdapter extends PageSelectionAdapter<TLRPC.User, PageHolder> {
        public MenuMentionUserAdapter(Context context) {
            super(context);
            setShowLoadMoreViewEnable(false);
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
        protected boolean isEnableForChild(PageHolder holder) {
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
        public PageHolder onCreateViewHolderForChild(ViewGroup parent, int viewType) {
            BackupImageView ivAvatar = new BackupImageView(getContext());
            ivAvatar.setRoundRadius(AndroidUtilities.dp(5.0f));
            ivAvatar.setLayoutParams(new RecyclerView.LayoutParams(AndroidUtilities.dp(30.0f), AndroidUtilities.dp(30.0f)));
            return new PageHolder(ivAvatar, 0);
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
        public void onBindViewHolderForChild(PageHolder holder, int position, TLRPC.User user) {
            BackupImageView ivAvatar = (BackupImageView) holder.itemView;
            AvatarDrawable drawable = new AvatarDrawable();
            drawable.setInfo(user);
            ivAvatar.setImage(ImageLocation.getForUser(user, false), "50_50", drawable, user);
        }
    }

    public static abstract class Menu {
        public int icon;
        public String leftTitle;
        public String rightTitle;
        protected String rightValue;
        public int type;

        public abstract String getRightValue();

        public boolean hasValue() {
            return !TextUtils.isEmpty(this.rightValue);
        }
    }

    public static class MenuMentionUser extends Menu {
        public List<TLRPC.User> users = new ArrayList();

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.PublishMenuAdapter.Menu
        public boolean hasValue() {
            return this.users.size() > 0;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.PublishMenuAdapter.Menu
        public String getRightValue() {
            return null;
        }
    }

    public static class MenuLocation extends Menu {
        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.PublishMenuAdapter.Menu
        public boolean hasValue() {
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.PublishMenuAdapter.Menu
        public String getRightValue() {
            return null;
        }

        public boolean hasAddress() {
            return false;
        }
    }

    public static class MenuTopic extends Menu {
        public HashMap<String, RespTopicBean.Item> topicMap = new HashMap<>();
        private List<RespTopicBean.Item> topics = new ArrayList();
        private ArrayList<TopicBean> topicBeans = new ArrayList<>();

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.PublishMenuAdapter.Menu
        public boolean hasValue() {
            return this.topicMap.size() > 0;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.PublishMenuAdapter.Menu
        public String getRightValue() {
            if (hasValue()) {
                this.rightValue = LocaleController.formatString("hasselectedtopics", R.string.hasselectedtopics, Integer.valueOf(this.topicMap.size()));
            } else if (!hasValue()) {
                this.rightValue = null;
            }
            return this.rightValue;
        }

        public List<RespTopicBean.Item> getRespTopics() {
            if (hasValue()) {
                this.topics.clear();
                for (Map.Entry<String, RespTopicBean.Item> entry : this.topicMap.entrySet()) {
                    this.topics.add(entry.getValue());
                }
            } else if (!hasValue()) {
                this.rightValue = null;
                this.topics.clear();
                this.topicMap.clear();
                this.topicBeans.clear();
            }
            return this.topics;
        }

        public ArrayList<TopicBean> getTopicBeans() {
            if (hasValue()) {
                this.topicBeans.clear();
                for (Map.Entry<String, RespTopicBean.Item> entry : this.topicMap.entrySet()) {
                    TopicBean topic = new TopicBean(entry.getValue().TopicName, entry.getValue().TopicID);
                    this.topicBeans.add(topic);
                }
            } else if (!hasValue()) {
                this.rightValue = null;
                this.topics.clear();
                this.topicMap.clear();
                this.topicBeans.clear();
            }
            return this.topicBeans;
        }
    }

    public static class MenuWhoCanWatch extends MenuMentionUser {
        public int privicyType;

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.PublishMenuAdapter.MenuMentionUser, im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.PublishMenuAdapter.Menu
        public String getRightValue() {
            if (hasValue()) {
                StringBuilder builder = new StringBuilder();
                for (TLRPC.User user : this.users) {
                    builder.append(UserObject.getName(user));
                }
                this.rightValue = builder.toString();
            } else if (!hasValue()) {
                this.rightValue = null;
                this.users.clear();
            }
            return this.rightValue;
        }
    }
}
