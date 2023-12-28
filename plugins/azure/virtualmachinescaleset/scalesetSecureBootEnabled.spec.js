var expect = require('chai').expect;
var scaleSetSecureBootEnabled = require('./scalesetSecureBootEnabled');

const virtualMachineScaleSets = [
    {
        'name': 'test-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
        'virtualMachineProfile': {
            "securityProfile": {
            "uefiSettings": {
              "secureBootEnabled": true,
              "vTpmEnabled": true
            },
            "encryptionAtHost": true,
            "securityType": "TrustedLaunch"
          },
        }
    },
    {
        'name': 'test-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
        'virtualMachineProfile': {
            "securityProfile": {
            "uefiSettings": {
              "secureBootEnabled": false,
              "vTpmEnabled": false
            },
            "encryptionAtHost": true,
            "securityType": "Standard"
          },
        }
    }
];

const createCache = (virtualMachineScaleSets) => {
    let machine = {};
    if (virtualMachineScaleSets) {
        machine['data'] = virtualMachineScaleSets;
    }
    return {
        virtualMachineScaleSets: {
            listAll: {
                'eastus': machine
            }
        }
    };
};

describe('scaleSetSecureBootEnabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual machine scale sets', function(done) {
            const cache = createCache([]);
            scaleSetSecureBootEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machine Scale Sets found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machine scale sets', function(done) {
            const cache = createCache();
            scaleSetSecureBootEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Machine Scale Sets');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Virtual Machine Scale Set has secure boot enabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]]);
            scaleSetSecureBootEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Machine Scale Set has secure boot enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Virtual Machine Scale Set has secure boot disabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[1]]);
            scaleSetSecureBootEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual Machine Scale Set does not have secure boot enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});