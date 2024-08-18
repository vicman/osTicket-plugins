<?php

require_once INCLUDE_DIR . 'class.plugin.php';

class S3StoragePluginConfig extends PluginConfig {

    // Provide compatibility function for versions of osTicket prior to
    // translation support (v1.9.4)
    static function translate() {
        if (!method_exists('Plugin', 'translate')) {
            return array(
                function($x) { return $x; },
                function($x, $y, $n) { return $n != 1 ? $y : $x; },
            );
        }
        return Plugin::translate('auth-ldap');
    }

    function getOptions() {
        list($__, $_N) = self::translate();
        return array(
            'bucket' => new TextboxField(array(
                'label' => $__('S3 Bucket'),
                'configuration' => array('size'=>40),
            )),
            'folder' => new TextboxField(array(
                'label' => $__('S3 Folder Path'),
                'configuration' => array('size'=>40),
            )),
            'storage_type' => new ChoiceField(array(
                'label' => $__('Storage Type'),
                'configuration' => array('data-name'=>'storage_type'),
                'choices' => array(
                    'amazon_s3' => $__('Amazon S3 Storage'),
                    's3_compatible' => $__('S3 Compatible Storage'),
                ),
                'default' => 'amazon_s3',
            )),
            'rest-endpoint' => new TextboxField(array(
                'label' => $__('REST Endpoint'),
                'hint' => $__('Specify S3-compatible API endpoint (ex: https://s3.wasabisys.com)'),
                'configuration' => array('size'=> 40, 'length'=> 80),
                'visibility' => new VisibilityConstraint(
                    new Q(array('storage_type__eq'=> 's3_compatible')),
                    VisibilityConstraint::HIDDEN
                ),
            )),
            'rest-region' => new TextboxField(array(
                'label' => $__('REST Region'),
                'hint' => $__('Specify S3-compatible API Region (ex:us-east-1)'),
                'configuration' => array('size'=>30),
                'visibility' => new VisibilityConstraint(
                    new Q(array('storage_type__eq'=> 's3_compatible')),
                    VisibilityConstraint::HIDDEN
                ),
            )),
            'aws-region' => new ChoiceField(array(
                'label' => $__('AWS Region'),
                'choices' => array(
                    '' => 'US Standard',
                    'us-east-1' => 'US East (N. Virginia)',
                    'us-east-2' => 'US East (Ohio)',
                    'us-west-1' => 'US West (N. California)',
                    'us-west-2' => 'US West (Oregon)',
                    'af-south-1' => 'Africa (Cape Town)',
                    'ap-east-1' => 'Asia Pacific (Hong Kong)',
                    'ap-south-1' => 'Asia Pacific (Mumbai)',
                    'ap-northeast-3' => 'Asia Pacific (Osaka)',
                    'ap-northeast-2' => 'Asia Pacific (Seoul)',
                    'ap-southeast-1' => 'Asia Pacific (Singapore)',
                    'ap-southeast-2' => 'Asia Pacific (Sydney)',
                    'ap-northeast-1' => 'Asia Pacific (Tokyo)',
                    'ca-central-1' => 'Canada (Central)',
                    'cn-north-1' => 'China (Beijing)',
                    'cn-northwest-1' => 'China (Ningxia)',
                    'eu-central-1' => 'Europe (Frankfurt)',
                    'eu-west-1' => 'Europe (Ireland)',
                    'eu-west-2' => 'Europe (London)',
                    'eu-south-1' => 'Europe (Milan)',
                    'eu-west-3' => 'Europe (Paris)',
                    'eu-north-1' => 'Europe (Stockholm)',
                    'sa-east-1' => 'South America (São Paulo)',
                    'me-south-1' => 'Middle East (Bahrain)',
                    'us-gov-east-1' => 'AWS GovCloud (US-East)',
                    'us-gov-west-1' => 'AWS GovCloud (US-West)',
                ),
                'default' => '',
                //'visibility' => 'amazon_s3', // Visibilidad condicional
                'visibility' => new VisibilityConstraint(
                    new Q(array('storage_type__eq'=> 'amazon_s3')),
                    VisibilityConstraint::HIDDEN
                ),
            )),
            'acl' => new ChoiceField(array(
                'label' => $__('Default ACL for Attachments'),
                'choices' => array(
                    '' => $__('Use Bucket Default'),
                    'private' => $__('Private'),
                    'public-read' => $__('Public Read'),
                    'public-read-write' => $__('Public Read and Write'),
                    'authenticated-read' => $__('Read for AWS authenticated Users'),
                    'bucket-owner-read' => $__('Read for Bucket Owners'),
                    'bucket-owner-full-control' => $__('Full Control for Bucket Owners'),
                ),
                'default' => '',
            )),

            'access-info' => new SectionBreakField(array(
                'label' => $__('Access Information'),
            )),
            'aws-key-id' => new TextboxField(array(
                'required' => true,
                'configuration'=>array('length'=>64, 'size'=>40),
                'label' => $__('AWS Access Key ID'),
            )),
            'secret-access-key' => new TextboxField(array(
                'widget' => 'PasswordWidget',
                'required' => false,
                'configuration'=>array('length'=>64, 'size'=>40),
                'label' => $__('AWS Secret Access Key'),
            )),
        );
    }

    function pre_save(&$config, &$errors) {
        list($__, $_N) = self::translate();
        $credentials['credentials'] = array(
            'key' => $config['aws-key-id'],
            'secret' => $config['secret-access-key']
                ?: Crypto::decrypt($this->get('secret-access-key'), SECRET_SALT,
                        $this->getNamespace()),
        );
        
        if ($config['storage_type'] === 's3_compatible') {
            // Si el campo rest-endpoint está vacío, añade un error
            if (empty($config['rest-endpoint'])) {
                $this->getForm()->getField('rest-endpoint')->addError(
                    __('REST Endpoint is required for S3 Compatible Storage'));
                $errors['err'] = __('Please complete the required fields.');
            } elseif (!filter_var($config['rest-endpoint'], FILTER_VALIDATE_URL)) {
                $this->getForm()->getField('rest-endpoint')->addError(
                    __('Please enter a valid URL for the REST Endpoint'));
                $errors['err'] = __('Please enter a valid URL.');
            }

            if (empty($config['rest-region'])) {
                $this->getForm()->getField('rest-region')->addError(
                    __('REST Region is required for S3 Compatible Storage'));
                $errors['err'] = __('Please complete the required fields.');
            }
            $credentials['endpoint'] = $config['rest-endpoint'];
            $credentials['region'] = $config['rest-region'];
        }else{       
            if ($config['aws-region'])
                $credentials['region'] = $config['aws-region'];
        }

        if (!$credentials['credentials']['secret'])
            $this->getForm()->getField('secret-access-key')->addError(
                $__('Secret access key is required'));

        $credentials['version'] = '2006-03-01';
        $credentials['signature_version'] = 'v4';

        $s3 = new Aws\S3\S3Client($credentials);

        try {
            $s3->headBucket(array('Bucket'=>$config['bucket']));
        }
        catch (Aws\S3\Exception\AccessDeniedException $e) {
            $errors['err'] = sprintf(
                /* The %s token will become an upstream error message */
                $__('User does not have access to this bucket: %s'), (string)$e);
        }
        catch (Aws\S3\Exception\NoSuchBucketException $e) {
            $this->getForm()->getField('bucket')->addError(
                $__('Bucket does not exist'));
        }

        if (!$errors && $config['secret-access-key'])
            $config['secret-access-key'] = Crypto::encrypt($config['secret-access-key'],
                SECRET_SALT, $this->getNamespace());
        else
            $config['secret-access-key'] = $this->get('secret-access-key');

        return true;
    }
}
