package com.lljjcoder.style.citythreelist;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.lljjcoder.style.citylist.bean.CityInfoBean;
import com.lljjcoder.style.citylist.utils.CityListLoader;
import com.lljjcoder.style.citypickerview.C3949R;
import com.lljjcoder.style.citythreelist.CityAdapter;
import com.lljjcoder.widget.RecycleViewDividerForList;
import java.util.ArrayList;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class AreaActivity extends Activity {
    private TextView mCityNameTv;
    private RecyclerView mCityRecyclerView;
    private ImageView mImgBack;
    private CityInfoBean mProCityInfo = null;
    private CityBean areaBean = new CityBean();

    private void initView() {
        this.mImgBack = (ImageView) findViewById(C3949R.id.img_left);
        this.mCityNameTv = (TextView) findViewById(C3949R.id.cityname_tv);
        this.mImgBack.setVisibility(0);
        this.mImgBack.setOnClickListener(new View.OnClickListener() { // from class: com.lljjcoder.style.citythreelist.AreaActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                AreaActivity.this.finish();
            }
        });
        RecyclerView recyclerView = (RecyclerView) findViewById(C3949R.id.city_recyclerview);
        this.mCityRecyclerView = recyclerView;
        recyclerView.setLayoutManager(new LinearLayoutManager(this));
        this.mCityRecyclerView.addItemDecoration(new RecycleViewDividerForList((Context) this, 0, true));
    }

    private void setData() {
        CityInfoBean cityInfoBean = this.mProCityInfo;
        if (cityInfoBean == null || cityInfoBean.getCityList().size() <= 0) {
            return;
        }
        TextView textView = this.mCityNameTv;
        StringBuilder m586H = C1499a.m586H("");
        m586H.append(this.mProCityInfo.getName());
        textView.setText(m586H.toString());
        final ArrayList<CityInfoBean> cityList = this.mProCityInfo.getCityList();
        if (cityList == null) {
            return;
        }
        CityAdapter cityAdapter = new CityAdapter(this, cityList);
        this.mCityRecyclerView.setAdapter(cityAdapter);
        cityAdapter.setOnItemClickListener(new CityAdapter.OnItemSelectedListener() { // from class: com.lljjcoder.style.citythreelist.AreaActivity.1
            @Override // com.lljjcoder.style.citythreelist.CityAdapter.OnItemSelectedListener
            public void onItemSelected(View view, int i2) {
                AreaActivity.this.areaBean.setName(((CityInfoBean) cityList.get(i2)).getName());
                AreaActivity.this.areaBean.setId(((CityInfoBean) cityList.get(i2)).getId());
                Intent intent = new Intent();
                intent.putExtra("area", AreaActivity.this.areaBean);
                AreaActivity.this.setResult(1001, intent);
                AreaActivity.this.finish();
            }
        });
    }

    @Override // android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(C3949R.layout.activity_citylist);
        this.mProCityInfo = (CityInfoBean) getIntent().getParcelableExtra(CityListLoader.BUNDATA);
        initView();
        setData();
    }
}
