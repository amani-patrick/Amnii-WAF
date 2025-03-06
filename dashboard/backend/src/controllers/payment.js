const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const {PrismaClient} = require('@prisma/client');
const prisma = new PrismaClient();

const processPayment=async(req,res)=>{
    const {planId,currency,amaount,paymentMethod}=req.body;
    try{
        user=req.user;
        const plan=plans.find(p=>p.id===planId);
        if(!plan){
            return res.status(400).json({message:'Invalid plan'});
        }
        try{
            let paymentIntent;
            let status='failed';
            if(paymentMethod.type==='card'){
                paymentIntent=await stripe.paymentIntents.create({
                    amount:plan.price*100,
                    currency:currency || 'usd',
                    payment_method:['card'],
                    confirm:true,
                });
                status='succeeded';
            }else if(paymentMethod.type==='paypal'){
                paymentIntent=await stripe.paymentIntents.create({
                    amount:plan.price*100,
                    currency:currency || 'usd',
                    payment_method:['paypal'],
                    confirm:true,
                });
                status='succeeded';
            }else if(paymentMethod.type==='MoMo'){
                paymentIntent=await stripe.paymentIntents.create({
                    amount:plan.price*100,
                    currency:currency || 'usd',
                    payment_method:['MoMo'],
                    confirm:true,
                });
                status='succeeded';
            }
            else{
                return res.status(400).json({message:'Unsupported payment method'});
            }
            const payment=await prisma.payment.create({
                data:{
                    amount:plan.price,
                    userId:user.id,
                    status,
                    paymentIntentId:paymentIntent.id,
                    paymentMethod:paymentMethod.type,
                    currency,
                },
            });
            res.json({message:'Payment successful',payment});
        }catch(error){
            console.error('Payment error:',error);
            return res.status(500).json({message:'Payment failed'});
        }
    }catch(error){
        console.error('Payment error:',error);
        return res.status(500).json({message:'Payment failed'});
    }
};

module.exports={processPayment};
