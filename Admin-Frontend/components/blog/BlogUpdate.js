import Link from 'next/link';
import { useState, useCallback, useEffect } from 'react';
import Router from 'next/router';
import dynamic from 'next/dynamic';
import { withRouter } from 'next/router';
import { getCookie, isAuth } from '../../actions/auth';
import { getTags } from '../../actions/tag';
import { singleBlog, updateBlog } from '../../actions/blog';

import EditorJs from "react-editor-js";
import { EDITOR_JS_TOOLS } from "./editorjs-constants";
// import ModalExample from './ModalExample'


import { API } from '../../config';
import {Button, Card, Layout, SkeletonBodyText, SkeletonDisplayText,
    SkeletonPage, TextContainer, EmptyState, OptionList, TextField, 
    MediaCard, Thumbnail,
    Frame, Image, Page, Toast } from '@shopify/polaris';
import { ResourcePicker, TitleBar } from '@shopify/app-bridge-react';
import ResourceListWithProducts from '../ResourceList';
import store from 'store-js';

const BlogUpdate = ({ shop, router }) => {

    const [title, setTitle] = useState('');
    const [body, setBody] = useState(false);
    const [tags, setTags] = useState([]);
    const [selectedTags, setSelectedTags] = useState([]); //polaris tags selected state
    const [selectedProducts, setSelectedProducts] = useState([]);
    const [editorInstance, setEditorInstance] = useState();

    const [modalState, setModalState] = useState(false);
   
    const handleTitleChange = useCallback((newValue) => setTitle(newValue), []);

    const [values, setValues] = useState({
        error: '',
        success: '',
        body: {}
    });

    const { error, success, formData } = values;
    console.log('selectedTags in BlogUpdate function', selectedTags);


    const token = getCookie('token');

    useEffect(() => {
        setValues({ ...values });
        initBlog();
        initTags();
    }, [router]);

    const initBlog = () => {
        if (router.query.slug) {
            singleBlog(router.query.slug).then(data => {
                console.log('blog data:', data);
                if (data.error) {
                    console.log(data.error);
                } else {
                    setTitle(data.title);
                    setBody(data.body);
                    setTagsArray(data.tags);
                    setSelectedProducts(data.selectedProducts)
                }
            });
        }
    };

    const setTagsArray = blogTags => {
        console.log('ran setTagsArray func with :', blogTags)
        let ta = [];
        blogTags ? blogTags.map((t, i) => {
            ta.push(t._id);
        }) : [];
        setSelectedTags(ta);
    };

    const initTags = () => {
        getTags(shop).then(data => {
            if (data.error) {
                setValues({ ...values, error: data.error });
            } else {
                setTags(data);
            }
        });
    };

    const showPolarisTags = () => {
        let tagsArray = tags ? tags.map((t, i) => (
            {value: t._id, label: t.name}
        )) : [];

        return (
            <Card>
              <OptionList
                title="Categorize and Increase Visibility with Tags"
                onChange={setSelectedTags}
                options={tagsArray}
                selected={selectedTags}
                allowMultiple
              />
            </Card>
        )
    };

    const showSelectedProducts = () => {
        console.log('selectedProducts in showSelectedProducts func',selectedProducts)
        return selectedProducts.length>0 ?  
             (
                <Card>
                <Button
                    onClick={() => setModalState(true)}
                  >Edit Promoted Products</Button>
                  {selectedProducts.map((product, i) => (
                      <div key={i}>
                      <h1>{product[0].title}</h1>
                      <Thumbnail
                        source={product[0].images[0] ? product[0].images[0].originalSrc : ''}
                        alt={product[0].descriptionHtml}
                      />
                      </div>
                  ))}
                </Card>
            ) : (   <Card>
                        <EmptyState
                            heading="Promote Related Products"
                            action={{
                              content: 'Select products',
                              onAction: () => setModalState(true),
                            }}
                            image={img}
                          >
                          <TextContainer>If no Products are selected, Tribet's AI will automatically
                           optimize for the bests Products to show alongside the post.</TextContainer>
                      </EmptyState>
                    </Card>
                 )   
    };

    const publishBlog = async () => {
        const savedData = await editorInstance.save();
        setBody([savedData]);
        let newlySelectedProducts = [];

        selectedProducts.forEach((p, i) => {
            newlySelectedProducts.push(p[0]);
        }); 
        
        updateBlog({title, savedData, body, selectedTags, selectedProducts: newlySelectedProducts}, token, router.query.slug).then(data => {
            if(data){
                if (data.error) {
                    setValues({ ...values, error: data.error });
                } else {
                    setValues({ ...values, title: '', success: `Blog titled "${data.title}" is successfully updated` });
                    if (isAuth() && isAuth().role === 1) {
                        // Router.replace(`/admin/crud/${router.query.slug}`);
                        Router.replace(`/admin`);
                    } else if (isAuth() && isAuth().role === 0) {
                        // Router.replace(`/user/crud/${router.query.slug}`);
                        Router.replace(`/user`);
                    }
                }
            }
           
        });
    }

    const showError = () => (
        <div className="alert alert-danger" style={{ display: error ? '' : 'none' }}>
            {error}
        </div>
    );

    const showSuccess = () => (
        <div className="alert alert-success" style={{ display: success ? '' : 'none' }}>
            {success}
        </div>
    );

    const handleSelection = (resources) => {
        const idsFromResources = resources.selection.map((product) => product.id);
        setModalState(false)
        console.log('selectedProducts added: ', resources);

        let newlySelectedProducts = [];
        resources.selection ? resources.selection.map((p, i) => {
            newlySelectedProducts.push([p]);
        }) : [];

        setSelectedProducts(newlySelectedProducts);
    };

    const img = 'https://cdn.shopify.com/s/files/1/0757/9955/files/empty-state.svg';

    return (
       <SkeletonPage title={title} type="input">
           {showSuccess()}
           {showError()}
           <ResourcePicker
              resourceType="Product"
              showVariants={false}
              open={modalState}
              onSelection={(resources) => handleSelection(resources)}
              onCancel={() => setModalState(false)}
            />
              <Layout>
                <Layout.Section>
                  <Card sectioned title="Title">
                    <TextField label="Post Title" value={title} onChange={handleTitleChange} />
                  </Card>
                  <Card sectioned title="Content">
                    {body ? (
                      <EditorJs
                        instanceRef={instance => setEditorInstance(instance)}
                        tools={EDITOR_JS_TOOLS}
                        data={body[0]}
                        onCompareBlocks={(newData, oldData) => {
                         console.log('newData === oldData :',newData === oldData)
                         console.log('oldData :',oldData)
                         console.log('newData:',newData) 
                        }}
                      />
                    ) : (<p>Loading</p>)}
                  </Card>
                </Layout.Section>
                <Layout.Section secondary>
                  <Card title="Promoted Products" subdued>
                    <Card.Section>
                        <TitleBar
                          primaryAction={{
                            content: 'Publish',
                            onAction: ()=>publishBlog(),
                          }}
                        />
                    {showSelectedProducts()}
                    </Card.Section>
                    <Card title="Tags">
                      <Card.Section>
                        {showPolarisTags()}
                      </Card.Section>
                    </Card>
                  </Card>
                </Layout.Section>
              </Layout>
        </SkeletonPage>
    );
};

export default withRouter(BlogUpdate);

