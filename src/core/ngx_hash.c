
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/**
 * 用于从hash表中查询元素
 * hash是散列表结构体的指针
 * key则是根据散列方法算出来的散列关键字
 * name和len则表示实际关键字的地址与长度
 * 
 * 返回散列表中关键字与name、len指定关键字完全相同的槽中，ngx_hash_elt_t结构体中value成员所指向的用户数据
 */
void *
ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len)
{
    ngx_uint_t       i;
    ngx_hash_elt_t  *elt;

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "hf:\"%*s\"", len, name);
#endif

    //计算所属槽位
    elt = hash->buckets[key % hash->size];

    //为null, 直接返回
    if (elt == NULL) {
        return NULL;
    }

    //elt->value为null, 表示当前已经遍历完了当前槽位的所有elt元素
    while (elt->value) {
        if (len != (size_t) elt->len) { //先比较len
            goto next;
        }

        for (i = 0; i < len; i++) {     //逐字符比较
            if (name[i] != elt->name[i]) {
                goto next;
            }
        }

        //找到了
        return elt->value;

    next:

        //跳转到下一个elt: elt->name[0] + elt->len + value指针。同时进行了缓冲区对齐
        elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len,
                                               sizeof(void *));
        continue;
    }

    return NULL;
}


/**
 * 通配符前置查找 *.test.com， 是一个递归查找的过程
 * 对于关键字为"*.test.com"这样带前置通配符的情况，建立了一个专用的前置通配符散列表，
 * 存储元素的关键字为com.test.。检索smtp.test.com是否匹配*.test.com，
 * 把要查询的smtp.test.com转化为com.test.字符串再开始查询
 * 
 * 先查找.com ；再查找test; 在查找smtp
 */
void *
ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len)
{
    void        *value;
    ngx_uint_t   i, n, key;

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "wch:\"%*s\"", len, name);
#endif

    n = len;

    //先找到最后一个.的位置
    while (n) {
        if (name[n - 1] == '.') {
            break;
        }

        n--;
    }

    //计算最后一段关键字hash值  如a.test.com -> com
    key = 0;

    for (i = n; i < len; i++) {
        key = ngx_hash(key, name[i]);
    }

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "key:\"%ui\"", key);
#endif

    //执行常规查找, 用最后一段com查找
    value = ngx_hash_find(&hwc->hash, key, &name[n], len - n);

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "value:\"%p\"", value);
#endif

    if (value) {    //找到了

        /*
         * the 2 low bits of value have the special meaning:
         *     00 - value is data pointer for both "example.com"
         *          and "*.example.com";
         *     01 - value is data pointer for "*.example.com" only;
         *     10 - value is pointer to wildcard hash allowing
         *          both "example.com" and "*.example.com";
         *     11 - value is pointer to wildcard hash allowing
         *          "*.example.com" only.
         */

        if ((uintptr_t) value & 2) {

            if (n == 0) {

                /* "example.com" */

                if ((uintptr_t) value & 1) {
                    return NULL;
                }

                hwc = (ngx_hash_wildcard_t *)
                                          ((uintptr_t) value & (uintptr_t) ~3);
                return hwc->value;
            }

            hwc = (ngx_hash_wildcard_t *) ((uintptr_t) value & (uintptr_t) ~3);

            value = ngx_hash_find_wc_head(hwc, name, n - 1);

            if (value) {
                return value;
            }

            return hwc->value;
        }

        if ((uintptr_t) value & 1) {

            if (n == 0) {

                /* "example.com" */

                return NULL;
            }

            return (void *) ((uintptr_t) value & (uintptr_t) ~3);
        }

        return value;
    }

    return hwc->value;
}


/**
 * 通配符后置查找 www.test.*， 是一个递归查找的过程
 * 对于关键字为"www.test.*"这样带后置通配符的情况,建立一个专用的后置通配符散列表，
 * 存储元素的关键字为www.test。检索www.test.cn是否匹配www.test.*，
 * 把要查询的www.test.cn转化为www.test字符串再开始查询
 * 
 * 先查找www, 再查找test, 再查找cn
 */

void *
ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len)
{
    void        *value;
    ngx_uint_t   i, key;

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "wct:\"%*s\"", len, name);
#endif

    key = 0;        //关键字hash

    for (i = 0; i < len; i++) {     //找到第一段www
        if (name[i] == '.') {
            break;
        }

        key = ngx_hash(key, name[i]);
    }

    if (i == len) {     //不包含.
        return NULL;
    }

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "key:\"%ui\"", key);
#endif

    //查找www
    value = ngx_hash_find(&hwc->hash, key, name, i);

#if 0
    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "value:\"%p\"", value);
#endif

    if (value) {

        //找到了
        /*
         * the 2 low bits of value have the special meaning:
         *     00 - value is data pointer;
         *     11 - value is pointer to wildcard hash allowing "example.*".
         */

        if ((uintptr_t) value & 2) {

            i++;

            hwc = (ngx_hash_wildcard_t *) ((uintptr_t) value & (uintptr_t) ~3);

            value = ngx_hash_find_wc_tail(hwc, &name[i], len - i);

            if (value) {
                return value;
            }

            return hwc->value;
        }

        return value;
    }

    return hwc->value;
}


/**
 * 带有通配符的key查询
 * 查找步骤：
 * 1. 在hash->hash中查找完全匹配
 * 2. 在hash->wc_head中进行前置通配符查找
 * 3. 在hash->wc_tail中进行后置通配符查找
 * 成功时返回元素指向的用户数据
 */
void *
ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key, u_char *name,
    size_t len)
{
    void  *value;

    //1.精确匹配查找
    if (hash->hash.buckets) {
        value = ngx_hash_find(&hash->hash, key, name, len);

        if (value) {
            return value;
        }
    }

    if (len == 0) {
        return NULL;
    }

    //2. 通配符前置查找
    if (hash->wc_head && hash->wc_head->hash.buckets) {
        value = ngx_hash_find_wc_head(hash->wc_head, name, len);

        if (value) {
            return value;
        }
    }

    //3. 通配符后置查找
    if (hash->wc_tail && hash->wc_tail->hash.buckets) {
        value = ngx_hash_find_wc_tail(hash->wc_tail, name, len);

        if (value) {
            return value;
        }
    }

    return NULL;
}


//单个elk的大小
#define NGX_HASH_ELT_SIZE(name)                                               \
    (sizeof(void *) + ngx_align((name)->key.len + 2, sizeof(void *)))

/**
 * 初始化完全匹配的hash表
 *  hinit：为hash表初始化结构指针
 *  names:为代表KV的ngx_hash_key_t数组，其长度为nelts
 */
ngx_int_t
ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names, ngx_uint_t nelts)
{
    u_char          *elts;
    size_t           len;
    u_short         *test;      //关键字段，是一个数组，每个元素存放当前槽位所有key占用空间的总长度
    ngx_uint_t       i, n, key, size, start, bucket_size;
    ngx_hash_elt_t  *elt, **buckets;

    //入参判断 桶个数max_size不能为0
    if (hinit->max_size == 0) {
        ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
                      "could not build %s, you should "
                      "increase %s_max_size: %i",
                      hinit->name, hinit->name, hinit->max_size);
        return NGX_ERROR;
    }

    //单个桶大小 不能大于65536 - ngx_cacheline_size
    if (hinit->bucket_size > 65536 - ngx_cacheline_size) {
        ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
                      "could not build %s, too large "
                      "%s_bucket_size: %i",
                      hinit->name, hinit->name, hinit->bucket_size);
        return NGX_ERROR;
    }

    //遍历存放key的数组，确保单个槽至少能容纳一个key。
    //即bucket_size应该大于任意一个key的大小
    for (n = 0; n < nelts; n++) {
        if (names[n].key.data == NULL) {        //忽略v为NULL的元素
            continue;
        }

        //NGX_HASH_ELT_SIZE计算单个key的大小。最后再加一个指针地址是为了存放NULL指针作为bucket结束的标识
        if (hinit->bucket_size < NGX_HASH_ELT_SIZE(&names[n]) + sizeof(void *))
        {
            ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
                          "could not build %s, you should "
                          "increase %s_bucket_size: %i",
                          hinit->name, hinit->name, hinit->bucket_size);
            return NGX_ERROR;
        }
    }

	/*
	 * test是用来做探测用的，探测的目标是在当前bucket的数量下，冲突发生的是否频繁。
	 * 过于频繁则需要调整桶的个数。
	 * 检查是否频繁的标准是：判断元素总长度和bucket桶的容量bucket_size做比较
	 */

    //初始化test为 存放max_size个u_short的数组。 每个元素存放的是i对应槽位上所有key元素的长度。
    test = ngx_alloc(hinit->max_size * sizeof(u_short), hinit->pool->log);
    if (test == NULL) {
        return NGX_ERROR;
    }

    /**
	 * 每个桶的元素实际所能容纳的空间大小
	 * 需要减去尾部的NULL指针结尾符号
	 */
    bucket_size = hinit->bucket_size - sizeof(void *);

    /* 估计hash表最少bucket数量；
     * 每个关键字元素需要的内存空间是 NGX_HASH_ELT_SIZE(&name[n])，至少需要占用两个指针的大小即2*sizeof(void *)
     * 这样来估计hash表所需的最小bucket数量
     * 因为关键字元素内存越小，则每个bucket所容纳的关键字元素就越多
     * 那么hash表的bucket所需的数量就越少，但至少需要一个bucket
     */
    start = nelts / (bucket_size / (2 * sizeof(void *)));
    start = start ? start : 1;      //最小为1

    if (hinit->max_size > 10000 && nelts && hinit->max_size / nelts < 100) {
        start = hinit->max_size - 1000;
    }

    /**
	 * 这边就是真正的探测逻辑
	 * 探测会遍历所有的元素，并且计算落到同一个bucket上元素长度的总和和bucket_size比较
	 * 如果超过了bucket_size，则说明需要调整
	 * 最终会探测出比较合适的桶的个数 ：size
	 */
    //逐步调整，找到一个能放下所有元素的桶数量。
    for (size = start; size <= hinit->max_size; size++) {

        //test为一个 u_short数组，数组个数为size。这里先进行清0
        ngx_memzero(test, size * sizeof(u_short));

        //遍历所有的key元素
        for (n = 0; n < nelts; n++) {
            if (names[n].key.data == NULL) {    //忽略v为null的
                continue;
            }

            key = names[n].key_hash % size;     //计算槽位号
            len = test[key] + NGX_HASH_ELT_SIZE(&names[n]); //len为对应槽位里所有元素的长度

#if 0
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "%ui: %ui %uz \"%V\"",
                          size, key, len, &names[n].key);
#endif

            //相同槽位里的元素长度已经大于bucket_size了，尝试下一个槽个数
            if (len > bucket_size) {
                goto next;
            }

            //更新当前槽累计元素的长度
            test[key] = (u_short) len;
        }

        //此处说明，使用size个槽，槽最大大小为bucket_size 可以容纳所有元素
        goto found;

    next:

        //继续尝试下一个槽大小 (增加槽个数)
        continue;
    }

    size = hinit->max_size;

    ngx_log_error(NGX_LOG_WARN, hinit->pool->log, 0,
                  "could not build optimal %s, you should increase "
                  "either %s_max_size: %i or %s_bucket_size: %i; "
                  "ignoring %s_bucket_size",
                  hinit->name, hinit->name, hinit->max_size,
                  hinit->name, hinit->bucket_size, hinit->name);

found:

    /* 到此已经找到合适的bucket数量，即为size
     * 重新初始化test数组元素，初始值为一个指针大小
     */
    //test数组初始化为每个元素都等于一个指针大小
    for (i = 0; i < size; i++) {
        test[i] = sizeof(void *);
    }

    //遍历所有key， 计算每个槽所有元素elt占用空间大小，存放到test[]中
    for (n = 0; n < nelts; n++) {
        if (names[n].key.data == NULL) {        //忽略值为NULL的元素
            continue;
        }

        key = names[n].key_hash % size;
        len = test[key] + NGX_HASH_ELT_SIZE(&names[n]);

        //单个槽的所有key长度超限
        if (len > 65536 - ngx_cacheline_size) {
            ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
                          "could not build %s, you should "
                          "increase %s_max_size: %i",
                          hinit->name, hinit->name, hinit->max_size);
            ngx_free(test);
            return NGX_ERROR;
        }

        test[key] = (u_short) len;
    }

    len = 0;    //为除去空槽外，其他所有槽位内key占用总长度

    for (i = 0; i < size; i++) {
        if (test[i] == sizeof(void *)) {        //空槽
            continue;
        }

        //调整成对齐到cacheline的大小
        test[i] = (u_short) (ngx_align(test[i], ngx_cacheline_size));

        //记录所有元素的总长度
        len += test[i];
    }

    if (hinit->hash == NULL) {
        hinit->hash = ngx_pcalloc(hinit->pool, sizeof(ngx_hash_wildcard_t)
                                             + size * sizeof(ngx_hash_elt_t *));
        if (hinit->hash == NULL) {
            ngx_free(test);
            return NGX_ERROR;
        }

         /* 计算buckets的起始位置 */
        buckets = (ngx_hash_elt_t **)
                      ((u_char *) hinit->hash + sizeof(ngx_hash_wildcard_t));

    } else {
        //buckets为size个(ngx_hash_elt_t *）指针
        buckets = ngx_pcalloc(hinit->pool, size * sizeof(ngx_hash_elt_t *));
        if (buckets == NULL) {
            ngx_free(test);
            return NGX_ERROR;
        }
    }

    //分配存放elts的数组, 对齐到cacheline大小
    elts = ngx_palloc(hinit->pool, len + ngx_cacheline_size);
    if (elts == NULL) {
        ngx_free(test);
        return NGX_ERROR;
    }

    elts = ngx_align_ptr(elts, ngx_cacheline_size);

    //遍历所有的槽位，初始化每个槽位指向的地址
    for (i = 0; i < size; i++) {
        if (test[i] == sizeof(void *)) {
            continue;
        }

        //buckets的每个元素指向elts数组
        buckets[i] = (ngx_hash_elt_t *) elts;
        elts += test[i];
    }

    /* 清空test数组，以便用来累计实际数据的长度，这里不计算结尾指针的长度 */
    for (i = 0; i < size; i++) {
        test[i] = 0;
    }

    //遍历所有的key, 将其放入到elts中
    for (n = 0; n < nelts; n++) {
        if (names[n].key.data == NULL) {
            continue;
        }

        //找到对应的槽位
        key = names[n].key_hash % size;
        //elt指向下一个可以使用的位置
        elt = (ngx_hash_elt_t *) ((u_char *) buckets[key] + test[key]);

        elt->value = names[n].value;
        elt->len = (u_short) names[n].key.len;

        //name转为小写
        ngx_strlow(elt->name, names[n].key.data, names[n].key.len);

        //更新对应槽位的累计长度
        test[key] = (u_short) (test[key] + NGX_HASH_ELT_SIZE(&names[n]));
    }

    //遍历所有的槽位, 设置bucket结束位置的null指针
    for (i = 0; i < size; i++) {
        if (buckets[i] == NULL) {
            continue;
        }

        elt = (ngx_hash_elt_t *) ((u_char *) buckets[i] + test[i]);

        //将每个槽位下一个可用位置置为NULL，标识当前槽的结束
        elt->value = NULL;
    }

    ngx_free(test); //释放test数组

    hinit->hash->buckets = buckets;
    hinit->hash->size = size;

#if 0

    for (i = 0; i < size; i++) {
        ngx_str_t   val;
        ngx_uint_t  key;

        elt = buckets[i];

        if (elt == NULL) {
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "%ui: NULL", i);
            continue;
        }

        while (elt->value) {
            val.len = elt->len;
            val.data = &elt->name[0];

            key = hinit->key(val.data, val.len);

            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "%ui: %p \"%V\" %ui", i, elt, &val, key);

            elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len,
                                                   sizeof(void *));
        }
    }

#endif

    return NGX_OK;
}


/**
 * 用于初始化通配符散列表（前置通配符或后置通配符）
 * hinit: 散列表初始化结构体指针
 * names: 存储着预添加到散列表中的元素， 这些元素的关键字要么含有前置通配符，要么含有后置通配符
 * nelts: 是names数组的元素个数
 */
/**
 * hint: 构造一个通配符hash表的一些参数的一个集合。关于该参数对应的类型的说明，请参见ngx_hash_t类型中ngx_hash_init函数的说明。
 * names: 构造此hash表的所有的通配符key的数组。特别要注意的是这里的key已经都是被预处理过的。
 *        例如：“*.abc.com”或者“.abc.com”被预处理完成以后，变成了“com.abc.”。而“mail.xxx.*”则被预处理为“mail.xxx.”。
 *        为什么会被处理这样？这里不得不简单地描述一下通配符hash表的实现原理。当构造此类型的hash表的时候，
 *        实际上是构造了一个hash表的一个“链表”，是通过hash表中的key“链接”起来的。比如：对于“*.abc.com”将会构造出2个hash表，
 *        第一个hash表中有一个key为com的表项，该表项的value包含有指向第二个hash表的指针，而第二个hash表中有一个表项abc，
 *        该表项的value包含有指向*.abc.com对应的value的指针。那么查询的时候，比如查询www.abc.com的时候，先查com，
 *        通过查com可以找到第二级的hash表，在第二级hash表中，再查找abc，依次类推，
 *        直到在某一级的hash表中查到的表项对应的value对应一个真正的值而非一个指向下一级hash表的指针的时候，查询过程结束。
 *        这里有一点需要特别注意的，就是names数组中元素的value所对应的值（也就是真正的value所在的地址）必须是能被4整除的，
 *        或者说是在4的倍数的地址上是对齐的。因为这个value的值的低两位bit是有用的，所以必须为0。如果不满足这个条件，
 *        这个hash表查询不出正确结果。
 * nelts: names数组元素的个数。
 */
ngx_int_t
ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts)
{
    size_t                len, dot_len;
    ngx_uint_t            i, n, dot;
    ngx_array_t           curr_names, next_names;
    ngx_hash_key_t       *name, *next_name;
    ngx_hash_init_t       h;
    ngx_hash_wildcard_t  *wdc;

    //初始化临时动态数组 curr_names， 元素类型为 ngx_hash_key_t
    if (ngx_array_init(&curr_names, hinit->temp_pool, nelts,
                       sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //初始化临时动态数组 next_names， 元素类型为 ngx_hash_key_t
    if (ngx_array_init(&next_names, hinit->temp_pool, nelts,
                       sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //遍历所有的关键字names， 构造ngx_hash_key_t，加入到curr_names动态数组中
    //是一个双重遍历
    for (n = 0; n < nelts; n = i) {

#if 0
        ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                      "wc0: \"%V\"", &names[n].key);
#endif

        dot = 0;        //标记names[n] 是否有.字符

        for (len = 0; len < names[n].key.len; len++) {
            if (names[n].key.data[len] == '.') {
                dot = 1;
                break;
            }
        }

        name = ngx_array_push(&curr_names);
        if (name == NULL) {
            return NGX_ERROR;
        }

        name->key.len = len;        //key长度只是到第一个.
        name->key.data = names[n].key.data;
        name->key_hash = hinit->key(name->key.data, name->key.len);
        name->value = names[n].value;

#if 0
        ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                      "wc1: \"%V\" %ui", &name->key, dot);
#endif

        dot_len = len + 1;

        if (dot) {
            len++;
        }

        next_names.nelts = 0;       //重置next_names数组长度

        //将names[n].key 第一个.剩余部分加入到next_names中
        if (names[n].key.len != len) {
            next_name = ngx_array_push(&next_names);
            if (next_name == NULL) {
                return NGX_ERROR;
            }

            next_name->key.len = names[n].key.len - len;        //第一个.的剩余部分
            next_name->key.data = names[n].key.data + len;
            next_name->key_hash = 0;
            next_name->value = names[n].value;

#if 0
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "wc2: \"%V\"", &next_name->key);
#endif
        }

        //遍历当前位置之后的所有names关键字
        for (i = n + 1; i < nelts; i++) {
            //比较第一个.之前部分
            if (ngx_strncmp(names[n].key.data, names[i].key.data, len) != 0) {
                break;
            }

            //如果相等， 如 test.com & test.cn
            if (!dot
                && names[i].key.len > len
                && names[i].key.data[len] != '.')
            {
                break;
            }

            //此处说明names[i]和names[n] 有相同的以.结尾的前缀， 将names[i]剩余部分加入到next_name数组
            next_name = ngx_array_push(&next_names);
            if (next_name == NULL) {
                return NGX_ERROR;
            }

            next_name->key.len = names[i].key.len - dot_len;
            next_name->key.data = names[i].key.data + dot_len;
            next_name->key_hash = 0;
            next_name->value = names[i].value;

#if 0
            ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
                          "wc3: \"%V\"", &next_name->key);
#endif
        }

        if (next_names.nelts) { //如果next_names中有元素

            h = *hinit;
            h.hash = NULL;

            //以next_names动态数组为key，重新创建一个二级hash
            if (ngx_hash_wildcard_init(&h, (ngx_hash_key_t *) next_names.elts,
                                       next_names.nelts)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            wdc = (ngx_hash_wildcard_t *) h.hash;

            if (names[n].key.len == len) {
                wdc->value = names[n].value;    //value指向的是用户数据
            }

            //name的值指向下一级hash wdc
            name->value = (void *) ((uintptr_t) wdc | (dot ? 3 : 2));

        } else if (dot) {
            name->value = (void *) ((uintptr_t) name->value | 1);
        }
    }

    //初始化curr_names动态数组组成的hash。这个hash是第一级hash.其元素的value指向第二级hash, 依次递归
    if (ngx_hash_init(hinit, (ngx_hash_key_t *) curr_names.elts,
                      curr_names.nelts)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/**
 * 字符串关键字hash函数, 返回hash值, 可以用作hash表计算key的hash
 */
ngx_uint_t
ngx_hash_key(u_char *data, size_t len)
{
    ngx_uint_t  i, key;

    key = 0;

    for (i = 0; i < len; i++) {
        key = ngx_hash(key, data[i]);
    }

    return key;
}


/**
 * 字符串关键字转为小写后的hash函数, 可以用作hash表计算key的hash
 * 将data转小写，同时返回hash
 */
ngx_uint_t
ngx_hash_key_lc(u_char *data, size_t len)
{
    ngx_uint_t  i, key;

    key = 0;

    for (i = 0; i < len; i++) {
        key = ngx_hash(key, ngx_tolower(data[i]));
    }

    return key;
}


/**
 * 小写的同时计算hash值，结果存入dst中
 * 返回hash值
 */
ngx_uint_t
ngx_hash_strlow(u_char *dst, u_char *src, size_t n)
{
    ngx_uint_t  key;

    key = 0;

    while (n--) {
        *dst = ngx_tolower(*src);
        key = ngx_hash(key, *dst);
        dst++;
        src++;
    }

    return key;
}


/**
 * 初始化 ngx_hash_keys_arrays_t。 向ha中添加元素前，必须先调用此方法
 * 
 * ngx_hash_keys_arrays_t用来构建hash表
 * 
 * type取值：NGX_HASH_SMALL NGX_HASH_LARGE， 标识初始化元素的多少
 */
ngx_int_t
ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type)
{
    ngx_uint_t  asize;

    if (type == NGX_HASH_SMALL) {
        asize = 4;
        ha->hsize = 107;

    } else {
        asize = NGX_HASH_LARGE_ASIZE;       //16384
        ha->hsize = NGX_HASH_LARGE_HSIZE;   //10007
    }

    //初始化存放精确匹配的key的动态数组 ngx_array_t ha->keys
    if (ngx_array_init(&ha->keys, ha->temp_pool, asize, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //初始化前置通配符关键字的动态数组 ngx_array_t ha->dns_wc_head
    if (ngx_array_init(&ha->dns_wc_head, ha->temp_pool, asize,
                       sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //初始化后置通配符关键字的动态数组 ngx_array_t ha->dns_wc_tail
    if (ngx_array_init(&ha->dns_wc_tail, ha->temp_pool, asize,
                       sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //一个简易的散列表，存放精确匹配的key。是一个数组，每个数组元素是一个ngx_array_t。用于快速检测重复key元素添加
    //每个数组元素存放的是位于相同槽位的key
    ha->keys_hash = ngx_pcalloc(ha->temp_pool, sizeof(ngx_array_t) * ha->hsize);
    if (ha->keys_hash == NULL) {
        return NGX_ERROR;
    }

    //一个简易的散列表，存放前置匹配的key。是一个数组，每个数组元素是一个ngx_array_t。用于快速检测重复key元素添加
    //每个数组元素存放的是位于相同槽位的key
    ha->dns_wc_head_hash = ngx_pcalloc(ha->temp_pool,
                                       sizeof(ngx_array_t) * ha->hsize);
    if (ha->dns_wc_head_hash == NULL) {
        return NGX_ERROR;
    }

    //一个简易的散列表，存放后置匹配的key。是一个数组，每个数组元素是一个ngx_array_t。用于快速检测重复key元素添加
    //每个数组元素存放的是位于相同槽位的key
    ha->dns_wc_tail_hash = ngx_pcalloc(ha->temp_pool,
                                       sizeof(ngx_array_t) * ha->hsize);
    if (ha->dns_wc_tail_hash == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/**
 * ngx_hash_keys_arrays_t是初始化通配符匹配hash所需的参数。
 * 本方法向向ngx_hash_keys_arrays_t的ha中加入一个散列表元素
 * 
 * key是添加元素的关键字
 * value 是关键字对应的用户数据指针
 * flags NGX_HASH_WILDCARD_KEY/NGX_HASH_READONLY_KEY/
 * 
 * flags:有两个标志位可以设置，NGX_HASH_WILDCARD_KEY和NGX_HASH_READONLY_KEY。同时要设置的使用逻辑与操作符就可以了。
 *       NGX_HASH_READONLY_KEY被设置的时候，在计算hash值的时候，key的值不会被转成小写字符，否则会。
 *       NGX_HASH_WILDCARD_KEY被设置的时候，说明key里面可能含有通配符，会进行相应的处理。如果两个标志位都不设置，传0。
 * 
 * 
 * 总体逻辑是，根据key是精确、前缀、后缀匹配，将其加入到ha.key_hash、dns_wc_tail、dns_wc_head 中
 * 
 */
ngx_int_t
ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key, void *value,
    ngx_uint_t flags)
{
    size_t           len;
    u_char          *p;
    ngx_str_t       *name;
    ngx_uint_t       i, k, n, skip, last;
    ngx_array_t     *keys, *hwc;
    ngx_hash_key_t  *hk;

    last = key->len;

    //1. 带有WILDCARD的key
    if (flags & NGX_HASH_WILDCARD_KEY) {

        /*
         * supported wildcards:
         *     "*.example.com", ".example.com", and "www.example.*"
         */

        n = 0;

        //遍历每个字符
        for (i = 0; i < key->len; i++) {

            if (key->data[i] == '*') {
                if (++n > 1) {      //限制只能有一个 *
                    return NGX_DECLINED;
                }
            }

            if (key->data[i] == '.' && key->data[i + 1] == '.') {
                return NGX_DECLINED;        //有两个连续的 .
            }

            if (key->data[i] == '\0') {     //不允许有'\0'
                return NGX_DECLINED;
            }
        }

        //如果是.开头的
        if (key->len > 1 && key->data[0] == '.') {
            skip = 1;
            goto wildcard;
        }

        //去掉.*前缀和后缀
        if (key->len > 2) {

            //后缀格式 *.xxxx
            if (key->data[0] == '*' && key->data[1] == '.') {
                skip = 2;
                goto wildcard;
            }

            //前缀格式xxx.*
            if (key->data[i - 2] == '.' && key->data[i - 1] == '*') {
                skip = 0;
                last -= 2;
                goto wildcard;
            }
        }

        if (n) { //n为字符*个数
            //有*，但既不是*.xxx格式,也不是xxx.*格式
            return NGX_DECLINED;
        }
    }

    /* exact hash */

    //2. 此处表示精确匹配
    k = 0;

    for (i = 0; i < last; i++) {
        //如果没有READONLY标识，将key转为小写
        if (!(flags & NGX_HASH_READONLY_KEY)) {
            key->data[i] = ngx_tolower(key->data[i]);
        }
        k = ngx_hash(k, key->data[i]);  //计算hash值
    }

    k %= ha->hsize; //hsize为槽个数

    /* check conflicts in exact hash */

    //找到k槽位对应的ngx_string动态数组
    name = ha->keys_hash[k].elts;

    if (name) {
        //遍历动态数组
        for (i = 0; i < ha->keys_hash[k].nelts; i++) {
            if (last != name[i].len) {
                continue;
            }

            //已经有相同name的key
            if (ngx_strncmp(key->data, name[i].data, last) == 0) {
                return NGX_BUSY;
            }
        }

    } else {
        //k槽位对应的动态数组不存在，创建一个
        if (ngx_array_init(&ha->keys_hash[k], ha->temp_pool, 4,
                           sizeof(ngx_str_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    //将其加入到k槽位对于的动态数组 ha->keys_hash 中
    name = ngx_array_push(&ha->keys_hash[k]);
    if (name == NULL) {
        return NGX_ERROR;
    }

    *name = *key;

    //构建包含key和value的hk, 加入动态数组ha->keys中
    hk = ngx_array_push(&ha->keys);
    if (hk == NULL) {
        return NGX_ERROR;
    }

    hk->key = *key;
    hk->key_hash = ngx_hash_key(key->data, last);
    hk->value = value;

    return NGX_OK;


    //3. 包含wildcard的关键字处理
wildcard:

    /* wildcard hash */

    //转为小写，同时计算hash（已经跳过了*.xx和xx.*中的.*。）
    k = ngx_hash_strlow(&key->data[skip], &key->data[skip], last - skip);

    k %= ha->hsize;

    if (skip == 1) {    //.xxx格式, 去掉. 按精确匹配处理

        /* check conflicts in exact hash for ".example.com" */

        //查看精确匹配keys_hash中是否有相同的关键字
        name = ha->keys_hash[k].elts;

        if (name) {
            len = last - skip;

            for (i = 0; i < ha->keys_hash[k].nelts; i++) {
                if (len != name[i].len) {
                    continue;
                }

                //比较，跳过第一个字符.
                if (ngx_strncmp(&key->data[1], name[i].data, len) == 0) {
                    return NGX_BUSY;    //找到返回失败
                }
            }

        } else {
            //初始化槽位上的动态数组
            if (ngx_array_init(&ha->keys_hash[k], ha->temp_pool, 4,
                               sizeof(ngx_str_t))
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }

        //将关键字加入到k槽位对于的动态数组中
        name = ngx_array_push(&ha->keys_hash[k]);
        if (name == NULL) {
            return NGX_ERROR;
        }

        name->len = last - 1;   //移除首个.

        //分配新的存储空间
        name->data = ngx_pnalloc(ha->temp_pool, name->len);
        if (name->data == NULL) {
            return NGX_ERROR;
        }

        //复制值
        ngx_memcpy(name->data, &key->data[1], name->len);
    }


    if (skip) {     //*.xxx格式

        /*
         * convert "*.example.com" to "com.example.\0"
         *      and ".example.com" to "com.example\0"
         */

        p = ngx_pnalloc(ha->temp_pool, last);
        if (p == NULL) {
            return NGX_ERROR;
        }

        len = 0;
        n = 0;

        //按.分割，转置后放到p对应的地址里
        for (i = last - 1; i; i--) {        //从后往前
            if (key->data[i] == '.') {  //按.分割
                ngx_memcpy(&p[n], &key->data[i + 1], len);
                n += len;
                p[n++] = '.';
                len = 0;
                continue;
            }

            len++;
        }

        if (len) {
            ngx_memcpy(&p[n], &key->data[1], len);
            n += len;
        }

        p[n] = '\0';

        hwc = &ha->dns_wc_head;
        keys = &ha->dns_wc_head_hash[k];

    } else {        //www.example.* 场景

        /* convert "www.example.*" to "www.example\0" */

        last++;

        p = ngx_pnalloc(ha->temp_pool, last);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_cpystrn(p, key->data, last);

        hwc = &ha->dns_wc_tail;
        keys = &ha->dns_wc_tail_hash[k];
    }


    /* check conflicts in wildcard hash */

    //检查相同通配符的关键字是否已经存在了
    name = keys->elts;

    if (name) { //name为对应槽位的动态数组
        len = last - skip;

        for (i = 0; i < keys->nelts; i++) {
            if (len != name[i].len) {
                continue;
            }

            //检查到重复元素
            if (ngx_strncmp(key->data + skip, name[i].data, len) == 0) {
                return NGX_BUSY;
            }
        }

    } else {    //初始化对应槽位的动态数组
        if (ngx_array_init(keys, ha->temp_pool, 4, sizeof(ngx_str_t)) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    //将本次key加入到对应槽位的动态数组中
    name = ngx_array_push(keys);
    if (name == NULL) {
        return NGX_ERROR;
    }

    name->len = last - skip;
    name->data = ngx_pnalloc(ha->temp_pool, name->len);
    if (name->data == NULL) {
        return NGX_ERROR;
    }

    //去掉通配符后加入
    ngx_memcpy(name->data, key->data + skip, name->len);


    //将本次的key加入到通配符动态数组中
    /* add to wildcard hash */

    hk = ngx_array_push(hwc);
    if (hk == NULL) {
        return NGX_ERROR;
    }

    hk->key.len = last - 1;
    hk->key.data = p;
    hk->key_hash = 0;
    hk->value = value;

    return NGX_OK;
}
