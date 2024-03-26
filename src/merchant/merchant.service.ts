import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import {
  MerchantEntity,
  OtpEntity,
  PaymentEntity,
  SessionEntity,
  UserEntity,
} from './merchant.entity';
import { Repository } from 'typeorm';
import {
  Merchant_ProfileDTO,
  MerchantDto,
  LoginDTO,
  Payment_ReceiverDTO,
} from './merchant.dto';
import { MapperService } from './mapper.service';
import { JwtService } from '@nestjs/jwt';
import { MailerService } from '@nestjs-modules/mailer';
import { instanceToPlain } from 'class-transformer';
import { Request } from 'express';
import * as bcrypt from 'bcrypt';

@Injectable()
export class MerchantService {
  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
    @InjectRepository(MerchantEntity)
    private merchantRepository: Repository<MerchantEntity>,
    @InjectRepository(PaymentEntity)
    private paymentRepository: Repository<PaymentEntity>,
    @InjectRepository(SessionEntity)
    private sessionRepository: Repository<SessionEntity>,
    @InjectRepository(OtpEntity)
    private otpRepository: Repository<OtpEntity>,

    private mailerService: MailerService,
    private mapperService: MapperService,
    private jwtService: JwtService,
  ) {}

  get_service(): string {
    return 'MerchantService is working!';
  }

  // Features =

  async Create_Signup(signup_info: LoginDTO): Promise<any> {
    const user = this.mapperService.dtoToEntity(signup_info, UserEntity);
    const previous_data = await this.userRepository.findOneBy({
      email: user.email,
    });
    if (previous_data === null) {
      const saved_user = await this.userRepository.save(user);
      return saved_user.id;
    } else {
      return -1;
    }
  }

  async Create_Merchant(merchant_info: MerchantDto): Promise<any> {
    try {
      const merchantEntity = this.mapperService.dtoToEntity(
        merchant_info,
        MerchantEntity,
      );

      const user = await this.userRepository.findOneBy({
        id: merchant_info.user_id,
      });

      merchantEntity.user = user;
      merchantEntity.image = 'temp.jpg';
      merchantEntity.receive_amount = 0;
      const number_existancy = await this.merchantRepository.findOneBy({
        phone: merchantEntity.phone,
      });
      if (number_existancy == null) {
        const saved_merchant =
          await this.merchantRepository.save(merchantEntity);
        return saved_merchant ? saved_merchant.id : -1;
      } else {
        throw new InternalServerErrorException('Phone Already exists');
      }
    } catch (e) {
      throw new InternalServerErrorException(
        'Merchant Service, Create Merchant Error = ' + e.message,
      );
    }
  }

  async Find_Merchant_By_Email(email: string): Promise<any> {
    const user = await this.userRepository.findOneBy({ email: email });
    const merchant = await this.merchantRepository.findOneBy({ user: user });
    //   Convert to Merchant Profile
    const merchant_Profile_DTO = this.mapperService.entityToDto(
      merchant,
      Merchant_ProfileDTO,
    );

    merchant_Profile_DTO.id = user.id;
    merchant_Profile_DTO.email = user.email;
    return merchant_Profile_DTO;
  }

  async Update_Own_Profile_Details(
    email: string,
    updated_data: Merchant_ProfileDTO,
  ): Promise<any> {
    try {
      const previous_data = await this.Find_Merchant_By_Email(email);
      const previous_user = await this.userRepository.findOneBy({
        email: email,
      });
      const previous_merchant = await this.merchantRepository.findOneBy({
        user: previous_user,
      });
      // If email Got Updated
      if (
        previous_data.email != updated_data.email &&
        updated_data.email != null &&
        updated_data.email != ''
      ) {
        await this.userRepository.update(previous_data.id, {
          email: updated_data.email,
        });
      }

      //   If name Got Updated
      if (
        previous_data.name != updated_data.name &&
        updated_data.name != null &&
        updated_data.name != ''
      ) {
        await this.merchantRepository.update(previous_merchant.id, {
          name: updated_data.name,
        });
      }

      //   If nid Got Updated
      if (
        previous_data.nid != updated_data.nid &&
        updated_data.nid != null &&
        updated_data.nid != ''
      ) {
        await this.merchantRepository.update(previous_merchant.id, {
          nid: updated_data.nid,
        });
      }

      //   If phone Got Updated
      if (
        previous_data.phone != updated_data.phone &&
        updated_data.phone != null &&
        updated_data.phone != ''
      ) {
        await this.merchantRepository.update(previous_merchant.id, {
          phone: updated_data.phone,
        });
      }

      //   If image Got Updated
      if (
        previous_data.image != updated_data.image &&
        updated_data.image != null &&
        updated_data.image != ''
      ) {
        await this.merchantRepository.update(previous_merchant.id, {
          image: updated_data.image,
        });
      }
      return updated_data;
    } catch (e) {
      return new InternalServerErrorException(e.message);
    }
  }

  async Add_Credits_Amount(
    email: string,
    paymentDTO: Payment_ReceiverDTO,
  ): Promise<any> {
    try {
      const amount = parseFloat(paymentDTO.amount);
      const user = await this.userRepository.findOneBy({ email: email });
      const merchant = await this.merchantRepository.findOneBy({ user: user });
      const final_amount = merchant.receive_amount + amount;

      // Create a Payment First

      const payment_decision = await this.Create_Payment(email, paymentDTO);
      console.log('Payment decision = ' + payment_decision);
      await this.merchantRepository.update(merchant.id, {
        receive_amount: final_amount,
      });
      return 1;
    } catch (e) {
      throw new InternalServerErrorException('Add Credit Error = ' + e.message);
    }
  }
  async Subtract_Credits_Amount(
    email: string,
    paymentDTO: Payment_ReceiverDTO,
  ): Promise<any> {
    try {
      const amount = parseFloat(paymentDTO.amount);
      const user = await this.userRepository.findOneBy({ email: email });
      const merchant = await this.merchantRepository.findOneBy({ user: user });
      console.log('Current amount = ' + merchant.receive_amount);
      if (merchant.receive_amount > 0) {
        const final_amount =
        merchant.receive_amount -
          (amount + (await this.calculate_charge(amount)));

        const payment_decision = await this.Create_Payment(email, paymentDTO);
        console.log('Payment decision = ' + payment_decision);
        await this.merchantRepository.update(merchant.id, {
          receive_amount: final_amount,
        });
        return 1;
      } else {
        throw new BadRequestException('Your Credit is already 0');
      }
    } catch (e) {
      throw new InternalServerErrorException(
        'Subtract Credit Error = ' + e.message,
      );
    }
  }

  // Not Needed, Handled from Controller
  async Update_Profile_Picture(
    email: string,
    image: string,
  ): Promise<Merchant_ProfileDTO> {
    const current_user = await this.userRepository.findOneBy({ email: email });
    const current_merchant = await this.merchantRepository.findOneBy({
      user: current_user,
    });

    if (current_merchant) {
      (await current_merchant).image = image;
      await this.merchantRepository.update((await current_merchant).id, {
        image: image,
      });
    }

    return await this.Find_Merchant_By_Email(email);
  }

  // Not Needed, Handled from Controller
  async Get_Profile_Picture(email: string, res: any): Promise<any> {
    const current_user = await this.userRepository.findOneBy({ email: email });
    const current_merchant = await this.merchantRepository.findOneBy({
      user: current_user,
    });
    // console.log("Current seller Image Getting = "+(await current_seller).Profile_Picture) // Working
    if (current_merchant) {
      res.sendFile((await current_merchant).image, {
        root: './assets/profile_images',
      });
    } else {
      throw new NotFoundException('Merchant data not found');
    }
  }

  async Create_Payment(
    email: string,
    payment: Payment_ReceiverDTO,
  ): Promise<any> {
    try {
      const user = await this.userRepository.findOneBy({ email: email });
      const payEntity = await this.mapperService.dtoToEntity(
        payment,
        PaymentEntity,
      );

      payEntity.user = user;
      payEntity.payment_date = await this.get_current_timestamp();
      payEntity.amount = parseFloat(payment.amount);

      const saved_data = await this.paymentRepository.save(payEntity);
      return saved_data ? saved_data.id : -1;
    } catch (e) {
      throw new InternalServerErrorException(
        'Merchant Service, Create Payment Error = ' + e.message,
      );
    }
  }

  async Get_All_Billing_Payment(email: string): Promise<PaymentEntity[]> {
    const user = await this.userRepository.findOneBy({ email: email });
    return this.paymentRepository.findBy({ user: user });
  }

  async Update_Password(req: Request, password: string): Promise<any> {
    try {
      const user = await this.get_user_from_Request(req);
      const update = await this.userRepository.update(user.id, {
        password: password,
      });
      return update.affected;
    } catch (e) {
      throw new InternalServerErrorException(
        'Update Password Merchant Service error = ' + e.message,
      );
    }
  }

  async Login(login_info: LoginDTO): Promise<UserEntity> {
    try {
      const user = await this.userRepository.findOneBy({
        email: login_info.email,
      });
      if (user != null) {
        return user;
      } else {
        throw new NotFoundException('There is no user using this email');
      }
    } catch (e) {
      throw new InternalServerErrorException(e.message);
    }
  }

  async ForgetPassword(email: string) {
    try {
      const user = await this.userRepository.findOneBy({ email: email });
      if (user != null) {
        //   Generate OTP
        const OTP = await this.Generate_OTP();
        const user_has_pin = await this.otpRepository.findOneBy({ user: user });
        if (user_has_pin) {
          console.log('Okay, Already have OTP. Needs to be updated');
          await this.otpRepository.update(user_has_pin.id, { otp: OTP });
          const user_has_pin_updated = await this.otpRepository.findOneBy({
            user: user,
          });
          console.log('Updated OTP = ' + user_has_pin_updated.otp);
        } else {
          const new_otp = new OtpEntity();
          new_otp.id = -1;
          new_otp.otp = OTP;
          new_otp.user = user;
          const saved_data = await this.otpRepository.save(new_otp);
          console.log('New OTP = ' + saved_data.otp);
        }

        //   Send the OTP through email
        const body =
          (await process.env.EMAIL_BODY_P1) + OTP + process.env.EMAIL_BODY_P2;
        await this.Send_Email(email, process.env.EMAIL_SUBJECT, body);
        const new_token = await new LoginDTO();
        new_token.email = email;
        new_token.password = 'temp';
        return await this.create_token(new_token);
      } else {
        return false;
      }
    } catch (e) {
      throw new InternalServerErrorException(
        'Forget Password Service Error = ' + e.message,
      );
    }
  }

  async otp_verification(req: Request, otp: string): Promise<any> {
    try {
      // Get the user by the email
      const user = await this.get_user_from_Request(req);
      console.log('Got the user' + user.email);
      //   Get the saved otp for the user
      const saved_otp_row_for_user = await this.otpRepository.findOneBy({
        user: user,
      });

      return saved_otp_row_for_user.otp == otp;
    } catch (e) {
      throw new InternalServerErrorException(
        'OTP verification service error = ' + e.message,
      );
    }
  }

  //   Additional Services || Not Features

  //region Supportive Functions

  async addToBlacklist(
    token: string,
    date_time: string,
    email: string,
  ): Promise<any> {
    try {
      const user = await this.userRepository.findOneBy({ email: email });
      const session = new SessionEntity();
      session.jwt_token = token;
      session.expiration_date = date_time;
      session.user = user;
      const saved_data = await this.sessionRepository.save(session);
      return saved_data.id > 0;
    } catch (e) {
      throw new InternalServerErrorException(e.message);
    }
  }

  async get_token_by_token(token: string): Promise<any> {
    try {
      return await this.sessionRepository.findOneBy({ jwt_token: token });
    } catch (e) {
      throw new InternalServerErrorException(e.message);
    }
  }

  async create_token(payload: LoginDTO): Promise<any> {
    try {
      const payloadObject = instanceToPlain(payload);
      return {
        access_token: await this.jwtService.signAsync(payloadObject, {
          secret: process.env.JWT_CUSTOM_SECRET, // Provide the same secret key used for OTP verification
        }),
      };
    } catch (e) {
      throw new InternalServerErrorException(
        'Create Token Service Error = ' + e.message,
      );
    }
  }

  async decode_token(token: string): Promise<any> {
    try {
      const decoded = await this.jwtService.verifyAsync(token, {
        secret: process.env.JWT_CUSTOM_SECRET,
      });
      return decoded;
    } catch (error) {
      // Handle decoding error
      throw new Error('Failed to decode token');
    }
  }
  async Send_Email(
    emailTo: string,
    emailSubject: string,
    emailBody: string,
  ): Promise<any> {
    try {
      return await this.mailerService.sendMail({
        to: emailTo,
        subject: emailSubject,
        text: emailBody,
      });
    } catch (e) {
      throw new InternalServerErrorException(e.message);
    }
  }

  async Generate_OTP(): Promise<any> {
    return (Math.floor(Math.random() * 900000) + 100000).toString();
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    try {
      const [type, token] = request.headers.authorization?.split(' ') ?? [];
      return type === 'Bearer' ? token : undefined;
    } catch (e) {
      throw new InternalServerErrorException(
        'extract Token From Header Merchant service error = ' + e.message,
      );
    }
  }

  async get_user_from_Request(req: Request): Promise<UserEntity> {
    try {
      const token = await this.extractTokenFromHeader(req);
      const decoded_object_login_dto = await this.decode_token(token);
      // Get the user by the email
      return await this.userRepository.findOneBy({
        email: decoded_object_login_dto.email,
      });
    } catch (e) {
      throw new InternalServerErrorException(
        'Get user from request Merchant service error = ' + e.message,
      );
    }
  }

  async calculate_charge(amount: number): Promise<number> {
    try {
      return amount * 0.02;
    } catch (e) {
      throw new InternalServerErrorException(
        'Charge Calculation error = ' + e.message,
      );
    }
  }

  async updateMerchant_SingleInfo(id: number, column: string, data: any) {
    const updateData = {};
    updateData[column] = data;

    await this.merchantRepository.update(id, updateData);
  }

  async get_current_timestamp(): Promise<string> {
    return new Date().toISOString();
  }

  async user_validity(email: string, password: string): Promise<boolean> {
    try {
      const saved_user = await this.userRepository.findOneBy({ email: email });
      if (!saved_user) {
        return false; // User not found, return false
      }

      return await bcrypt.compare(password, saved_user.password);
    } catch (e) {
      throw new InternalServerErrorException(
        'Merchant Service, user validity Error = ' + e.message,
      );
    }
  }

  //endregion Supportive Functions
}
